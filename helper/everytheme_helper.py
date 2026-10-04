#!/usr/bin/env python3
"""
EveryTheme helper daemon
========================

The security + networking brain behind the EveryTheme Omarchy shell plugin.

EveryTheme keeps the theme on a set of devices you own in sync. The QML bar
widget is only a view: this daemon owns device identity, peer discovery, the
pairing handshake, the authenticated command channel, and applying/broadcasting
theme changes.

Design goals (see ../README.md for the full threat model):

* Reachability is scoped, not trusted. The command listener only binds to
  private / link-local / VPN addresses. It is never exposed to the WAN, and no
  NAT traversal is performed.
* Identity is cryptographic. Each device has a self-signed Ed25519 certificate.
  Its SHA-256 fingerprint *is* the device id. Commands are carried over mutual
  TLS and are only accepted from a certificate that was explicitly pinned
  during pairing.
* Consent is explicit. A device only becomes trusted through a pairing flow
  that requires a one-time token (QR) or short code shown on the other device.
  Knowing someone's WAN IP is not enough to pair, and an unpaired peer cannot
  complete the normal TLS handshake at all.

Only the Python standard library and the `openssl` binary (present on Arch)
are required. No pip packages.

Modes
-----

  daemon            Run the long-lived daemon (spawned by the shell plugin).
  notify-theme T    Called by the installed theme-set hook. Forwards a locally
                    observed theme change to the running daemon.
  status            Print a JSON status snapshot (debugging).
  selftest          Run the built-in end-to-end security self-test.

The daemon speaks newline-delimited JSON over a Unix socket
($XDG_RUNTIME_DIR/everytheme.sock). The shell plugin connects as a client to
read state and issue commands (pair.start, pair.accept, peer.remove,
peer.enabled, theme.set, ...).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PROTOCOL_VERSION = 1
TCP_PORT = 45892
DISCOVERY_PORT = 45893
BEACON_INTERVAL = 5.0
PEER_TTL = 20.0
PAIR_TTL = 120.0
PAIR_MAX_ATTEMPTS = 5
PAIR_PBKDF2_ITERS = 200_000
TS_WINDOW = 300.0          # accept commands whose timestamp is within +/- 5 min
APPLY_SUPPRESS = 90.0      # ignore our own theme hook for this long after a remote apply
CONNECT_TIMEOUT = 5.0
DEFAULT_STATE_DIR = Path.home() / ".config" / "omarchy" / "everytheme"
ALLOWED_COMMANDS = {"theme.set", "ping", "wallpaper.ref", "wallpaper.set"}

# Wallpaper sync: a receiver must never be able to make us buffer an unbounded
# file, so the transfer is size-capped and only known image formats are kept.
WALLPAPER_MAX_BYTES = 25 * 1024 * 1024
WALLPAPER_POLL = 2.0
WALLPAPER_SUPPRESS = 30.0
IMAGE_MAGIC = (
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"BM", ".bmp"),
)


def detect_image_ext(data: bytes) -> str | None:
    for magic, ext in IMAGE_MAGIC:
        if data.startswith(magic):
            return ext
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


def current_background_path() -> str:
    link = Path.home() / ".local" / "state" / "omarchy" / "current" / "background"
    try:
        resolved = os.path.realpath(link)
        return resolved if os.path.isfile(resolved) else ""
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# small utilities
# --------------------------------------------------------------------------- #

def now() -> float:
    return time.time()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def b32e(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def cert_fingerprint(der: bytes) -> str:
    """Full base32 SHA-256 fingerprint of an X.509 certificate (DER)."""
    return b32e(sha256(der))


def device_id_from_der(der: bytes) -> str:
    """Human device id: first 26 chars of the certificate fingerprint."""
    return cert_fingerprint(der)[:26]


def pem_to_der(pem: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert(pem)


def der_to_pem(der: bytes) -> str:
    return ssl.DER_cert_to_PEM_cert(der)


def is_private_addr(ip: str) -> bool:
    """True for addresses that are plausibly on our LAN or a VPN overlay."""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if addr.is_loopback:
        return False
    if addr.is_private or addr.is_link_local:
        return True
    if isinstance(addr, ipaddress.IPv4Address):
        # CGNAT range used by Tailscale and carrier NAT.
        return addr in ipaddress.ip_network("100.64.0.0/10")
    # IPv6 unique-local fc00::/7 is covered by is_private; keep local check.
    return False


def is_local_source(ip: str) -> bool:
    """Source address allowed to reach the command listener.

    The listener is normally only bound to private/VPN addresses, so a peer's
    source is private. Loopback is accepted too so a local same-machine test or
    client can run without weakening the certificate requirement.
    """
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return addr.is_loopback or is_private_addr(ip)


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def atomic_write_json(path: Path, obj, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True).encode(), mode)


def load_json(path: Path, default):
    try:
        with open(path, "rb") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return default


def log(*args) -> None:
    print("[everytheme]", *args, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# local network interfaces
# --------------------------------------------------------------------------- #

def local_ipv4_addresses() -> list[tuple[str, int]]:
    """Return (address, prefixlen) pairs suitable for scoped binding.

    Uses `ip -j addr` (iproute2). Falls back to a UDP-connect trick.
    """
    result: list[tuple[str, int]] = []
    ip_bin = shutil.which("ip")
    if ip_bin:
        try:
            out = subprocess.check_output([ip_bin, "-j", "addr", "show"], text=True)
            for iface in json.loads(out):
                for info in iface.get("addr_info", []):
                    if info.get("family") != "inet":
                        continue
                    addr = info.get("local")
                    plen = int(info.get("prefixlen", 24))
                    if addr and is_private_addr(addr):
                        result.append((addr, plen))
        except (subprocess.SubprocessError, ValueError):
            pass
    if result:
        return result
    # Fallback: whatever route the kernel would pick. Exclude public / fallback.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        addr = s.getsockname()[0]
        s.close()
        if is_private_addr(addr):
            result.append((addr, 24))
    except OSError:
        pass
    return result


def broadcast_address(addr: str, prefixlen: int) -> str:
    net = ipaddress.ip_network(f"{addr}/{prefixlen}", strict=False)
    return str(net.broadcast_address)


# --------------------------------------------------------------------------- #
# identity
# --------------------------------------------------------------------------- #

class Identity:
    """Self-signed Ed25519 certificate + key for this device."""

    def __init__(self, base: Path):
        self.dir = base / "identity"
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cert_path = self.dir / "cert.pem"
        self.key_path = self.dir / "key.pem"
        self._ensure()
        self.cert_pem = self.cert_path.read_text()
        self.der = pem_to_der(self.cert_pem)
        self.fingerprint = cert_fingerprint(self.der)
        self.id = self.fingerprint[:26]
        self.name = socket.gethostname() or "omarchy"

    def _ensure(self) -> None:
        if self.cert_path.exists() and self.key_path.exists():
            return
        openssl = shutil.which("openssl")
        if not openssl:
            raise RuntimeError("openssl binary is required to create a device identity")
        cmd = [
            openssl, "req", "-x509", "-newkey", "ed25519",
            "-keyout", str(self.key_path), "-out", str(self.cert_path),
            "-days", "3650", "-nodes", "-subj", "/CN=everytheme",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(self.key_path, 0o600)
        os.chmod(self.cert_path, 0o644)

    def address_list(self) -> list[str]:
        return [addr for addr, _ in local_ipv4_addresses()]


# --------------------------------------------------------------------------- #
# peer store
# --------------------------------------------------------------------------- #

class PeerStore:
    """Trusted peers, persisted to peers.json. The cert is the identity."""

    def __init__(self, base: Path):
        self.path = base / "peers.json"
        self.base = base
        raw = load_json(self.path, {})
        self.peers: dict[str, dict] = {}
        for peer in raw.get("peers", []):
            try:
                der = pem_to_der(peer["cert"])
            except Exception:
                continue
            fp = cert_fingerprint(der)
            peer.setdefault("id", fp[:26])
            peer["fp"] = fp
            peer.setdefault("addresses", [])
            peer.setdefault("port", TCP_PORT)
            peer.setdefault("enabled", True)
            peer.setdefault("paired_at", 0)
            peer.setdefault("last_seq", 0)
            peer.setdefault("out_seq", 0)
            self.peers[fp] = peer
        self.rebuild_trust_bundle()

    def save(self) -> None:
        atomic_write_json(self.path, {"version": 1, "peers": list(self.peers.values())})

    def rebuild_trust_bundle(self) -> None:
        """A CA bundle of every pinned peer cert (self-signed => its own CA)."""
        bundle = "".join(peer["cert"] if peer["cert"].endswith("\n") else peer["cert"] + "\n"
                         for peer in self.peers.values())
        atomic_write(self.base / "trust.pem", bundle.encode())

    def by_fp(self, fp: str) -> dict | None:
        return self.peers.get(fp)

    def add(self, id_: str, name: str, cert_pem: str, addresses: list[str],
            port: int = TCP_PORT) -> dict:
        der = pem_to_der(cert_pem)
        fp = cert_fingerprint(der)
        peer = {
            "id": fp[:26],
            "name": name or (fp[:8]),
            "cert": cert_pem if cert_pem.endswith("\n") else cert_pem + "\n",
            "fp": fp,
            "addresses": [a for a in addresses if a],
            "port": int(port),
            "enabled": True,
            "paired_at": int(now()),
            "last_seq": 0,
            "out_seq": 0,
        }
        self.peers[fp] = peer
        self.save()
        self.rebuild_trust_bundle()
        return peer

    def remove(self, id_: str) -> bool:
        for fp, peer in list(self.peers.items()):
            if peer["id"] == id_ or fp == id_:
                del self.peers[fp]
                self.save()
                self.rebuild_trust_bundle()
                return True
        return False

    def set_enabled(self, id_: str, enabled: bool) -> bool:
        for peer in self.peers.values():
            if peer["id"] == id_:
                peer["enabled"] = bool(enabled)
                self.save()
                return True
        return False

    def touch_endpoint(self, id_: str, addresses: list[str], port: int = 0) -> None:
        for peer in self.peers.values():
            if peer["id"] == id_:
                changed = False
                merged = list(dict.fromkeys([*addresses, *peer.get("addresses", [])]))[:8]
                if merged != peer.get("addresses"):
                    peer["addresses"] = merged
                    changed = True
                if port and int(port) != int(peer.get("port", 0)):
                    peer["port"] = int(port)
                    changed = True
                if changed:
                    self.save()
                return


# --------------------------------------------------------------------------- #
# TLS contexts
# --------------------------------------------------------------------------- #

def _load_bundle(ctx: ssl.SSLContext, trust_bundle: Path) -> None:
    # An empty CA bundle is normal on a fresh install (no peers yet). OpenSSL
    # rejects an empty cafile, so only load it once a peer has been pinned.
    try:
        if trust_bundle.exists() and trust_bundle.stat().st_size > 0:
            ctx.load_verify_locations(cafile=str(trust_bundle))
    except OSError:
        pass


def server_context(identity: Identity, trust_bundle: Path, *, verify_peers: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(identity.cert_path), str(identity.key_path))
    if verify_peers:
        ctx.verify_mode = ssl.CERT_REQUIRED
        _load_bundle(ctx, trust_bundle)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False
    return ctx


def client_context(identity: Identity, trust_bundle: Path, *, verify_server: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(identity.cert_path), str(identity.key_path))
    ctx.check_hostname = False
    if verify_server:
        ctx.verify_mode = ssl.CERT_REQUIRED
        _load_bundle(ctx, trust_bundle)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# --------------------------------------------------------------------------- #
# theme handling
# --------------------------------------------------------------------------- #

def omarchy_bin() -> str:
    return shutil.which("omarchy") or "/usr/share/omarchy/bin/omarchy"


class ThemeManager:
    def __init__(self):
        self.theme_dirs = [
            Path("/usr/share/omarchy/themes"),
            Path.home() / ".config" / "omarchy" / "themes",
        ]
        self._cached: tuple[float, set[str]] = (0.0, set())

    def available(self) -> set[str]:
        stamp, cached = self._cached
        if now() - stamp < 30 and cached:
            return cached
        themes: set[str] = set()
        for base in self.theme_dirs:
            try:
                for entry in base.iterdir():
                    if entry.is_dir():
                        themes.add(entry.name)
            except OSError:
                continue
        self._cached = (now(), themes)
        return themes

    def current(self) -> str:
        # theme.name holds the slug (e.g. "cyberphunk"); `omarchy theme current`
        # returns a prettified display name, which will not match a directory.
        name_file = Path.home() / ".local" / "state" / "omarchy" / "current" / "theme.name"
        try:
            slug = name_file.read_text().strip()
            if slug:
                return slug
        except OSError:
            pass
        try:
            out = subprocess.check_output([omarchy_bin(), "theme", "current"], text=True,
                                          stderr=subprocess.DEVNULL, timeout=10)
            return out.strip().lower().replace(" ", "-")
        except (subprocess.SubprocessError, OSError):
            return ""

    def apply(self, theme: str) -> bool:
        if theme not in self.available():
            log(f"refusing unknown theme {theme!r}")
            return False
        if theme == self.current():
            return True
        try:
            subprocess.run([omarchy_bin(), "theme", "set", theme], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            return True
        except (subprocess.SubprocessError, OSError) as exc:
            log(f"failed to apply theme {theme!r}: {exc}")
            return False

    # ---- wallpaper ------------------------------------------------------ #
    def current_theme_backgrounds(self) -> Path:
        return Path.home() / ".local" / "state" / "omarchy" / "current" / "theme" / "backgrounds"

    def theme_dir(self, slug: str) -> Path | None:
        try:
            out = subprocess.check_output([omarchy_bin(), "theme", "dir", slug], text=True,
                                          stderr=subprocess.DEVNULL, timeout=10).strip()
            if out and Path(out).is_dir():
                return Path(out)
        except (subprocess.SubprocessError, OSError):
            pass
        return None

    def set_background(self, path: str) -> bool:
        try:
            subprocess.run([omarchy_bin(), "theme", "bg", "set", path], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            return True
        except (subprocess.SubprocessError, OSError) as exc:
            log(f"failed to set background {path!r}: {exc}")
            return False

    def resolve_theme_background(self, slug: str, name: str) -> str:
        """Find a theme background on this device, preferring the live theme."""
        if name != os.path.basename(name):
            return ""  # reject any path component
        candidates = [self.current_theme_backgrounds() / name]
        theme_dir = self.theme_dir(slug) if slug else None
        if theme_dir:
            candidates.append(theme_dir / "backgrounds" / name)
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
        return ""


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #

class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, daemon: "Daemon"):
        self.daemon = daemon
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def datagram_received(self, data: bytes, addr):
        try:
            msg = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if msg.get("everytheme") != PROTOCOL_VERSION:
            return
        peer_id = str(msg.get("id", ""))
        if not peer_id or peer_id == self.daemon.identity.id:
            return
        if not is_local_source(addr[0]):
            return
        self.daemon.note_discovery(
            peer_id=peer_id,
            name=str(msg.get("name", peer_id[:8])),
            addr=addr[0],
            port=int(msg.get("port", self.daemon.port)),
            pair_port=int(msg.get("pair", 0) or 0),
        )


# --------------------------------------------------------------------------- #
# pairing
# --------------------------------------------------------------------------- #

def pair_key(secret: bytes, salt: bytes, strong: bool) -> bytes:
    if strong:
        prk = hmac.new(salt, secret, hashlib.sha256).digest()
    else:
        prk = hashlib.pbkdf2_hmac("sha256", secret, salt, PAIR_PBKDF2_ITERS, dklen=32)
    okm, block, counter = b"", b"", 1
    while len(okm) < 32:
        block = hmac.new(prk, block + b"everytheme-pair-v1" + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:32]


def pair_transcript(na: bytes, nb: bytes, der_a: bytes, der_b: bytes) -> bytes:
    return b"everytheme-pair-v1" + na + nb + der_a + der_b


def pair_proof(key: bytes, role: str, transcript: bytes) -> bytes:
    """Role-bound proof of knowledge of the pairing key.

    The two sides must never prove themselves with the same value. If they did,
    an unauthenticated server could simply echo the client's own proof back and
    have its certificate pinned without knowing the code/token. Binding the role
    ("client"/"server") into the MAC makes the server's proof one the client
    never emits, so it cannot be reflected.
    """
    return hmac.new(key, b"everytheme-pair/" + role.encode() + b"\x00" + transcript,
                    hashlib.sha256).digest()


class PairingServer:
    """Runs on the device that displays the code (the initiator)."""

    def __init__(self, daemon: "Daemon"):
        self.daemon = daemon
        self.code = f"{secrets.randbelow(1_000_000):06d}"
        self.token = b32e(secrets.token_bytes(16))
        self.expires = now() + PAIR_TTL
        self.attempts = 0
        self.port = 0
        # One listener per bound address. All are kept referenced so none is
        # garbage-collected, and all are closed when the window ends — a
        # multi-homed host must be reachable on whichever address the other
        # device can route to, and must not leave stale pairing ports open.
        self._servers: list[asyncio.AbstractServer] = []

    @property
    def active(self) -> bool:
        return bool(self._servers) and now() < self.expires

    async def start(self, hosts: list[str] | None = None) -> None:
        ctx = server_context(self.daemon.identity, self.daemon.store_bundle, verify_peers=False)
        addresses = hosts or self.daemon.bind_addresses()
        # Bind an ephemeral port on the first address, then try the same port on
        # the rest so a single advertised port covers every interface.
        first = await asyncio.start_server(self._handle, host=addresses[0], port=0, ssl=ctx)
        self.port = first.sockets[0].getsockname()[1]
        self._servers.append(first)
        for addr in addresses[1:]:
            try:
                self._servers.append(
                    await asyncio.start_server(self._handle, host=addr, port=self.port, ssl=ctx))
            except OSError:
                continue
        log(f"pairing window open on {len(self._servers)} addresses (port {self.port}, "
            f"expires in {PAIR_TTL:.0f}s)")

    async def close(self) -> None:
        servers, self._servers = self._servers, []
        for server in servers:
            server.close()
        for server in servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()

    def _select_secret(self, method: str) -> tuple[bytes, bool]:
        if method == "qr":
            return self.token.encode(), True
        return self.code.encode(), False

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if now() >= self.expires:
                return
            hello_b = await recv_json(reader)
            if hello_b.get("t") != "pair.hello":
                return
            der_b = b64d(hello_b["cert"])
            if device_id_from_der(der_b) != hello_b.get("id"):
                return
            method = str(hello_b.get("method", "code"))
            secret, strong = self._select_secret(method)
            nb = b64d(hello_b["nonce"])
            na = secrets.token_bytes(16)
            await send_json(writer, {
                "t": "pair.hello",
                "v": PROTOCOL_VERSION,
                "id": self.daemon.identity.id,
                "name": self.daemon.identity.name,
                "nonce": b64e(na),
                "cert": b64e(self.daemon.identity.der),
                "port": self.daemon.port,
            })
            key = pair_key(secret, na + nb, strong)
            transcript = pair_transcript(na, nb, self.daemon.identity.der, der_b)
            # Verify the client's role-bound proof.
            client_proof = pair_proof(key, "client", transcript)
            confirm_b = await recv_json(reader)
            got = b64d(confirm_b.get("mac", ""))
            if not hmac.compare_digest(client_proof, got):
                self.attempts += 1
                await send_json(writer, {"t": "pair.error", "reason": "bad-secret"})
                log(f"pairing rejected (attempt {self.attempts}/{PAIR_MAX_ATTEMPTS})")
                if self.attempts >= PAIR_MAX_ATTEMPTS:
                    await self.close()
                return
            # Success: pin the peer, prove our own role to the client, then close.
            peername = writer.get_extra_info("peername")
            peer = self.daemon.store.add(
                id_=hello_b.get("id", ""),
                name=hello_b.get("name", ""),
                cert_pem=der_to_pem(der_b),
                addresses=[peername[0]] if peername else [],
                port=int(hello_b.get("port", TCP_PORT)),
            )
            server_proof = pair_proof(key, "server", transcript)
            await send_json(writer, {"t": "pair.confirm", "mac": b64e(server_proof)})
            await self.daemon.peers_changed()
            await send_json(writer, {"t": "pair.done", "id": self.daemon.identity.id})
            log(f"paired with {peer['name']} ({peer['id']})")
            await self.close()
        except (asyncio.IncompleteReadError, ConnectionError, KeyError, ValueError) as exc:
            log(f"pairing error: {exc!r}")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()


async def run_pairing_client(daemon: "Daemon", host: str, port: int,
                             method: str, secret: str) -> dict:
    """Called on the device where the user entered/scanned the code."""
    ctx = client_context(daemon.identity, daemon.store_bundle, verify_server=False)
    nb = secrets.token_bytes(16)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=host, port=port, ssl=ctx, server_hostname="everytheme"),
            timeout=CONNECT_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        reason = str(exc) or "timed out"
        raise ValueError(
            f"could not reach {host}:{port} ({reason}) — are both devices on the same network?"
        ) from exc
    try:
        await send_json(writer, {
            "t": "pair.hello",
            "v": PROTOCOL_VERSION,
            "method": method,
            "id": daemon.identity.id,
            "name": daemon.identity.name,
            "nonce": b64e(nb),
            "cert": b64e(daemon.identity.der),
            "port": daemon.port,
        })
        hello_a = await recv_json(reader)
        if hello_a.get("t") != "pair.hello":
            raise ValueError("peer did not start pairing")
        der_a = b64d(hello_a["cert"])
        if device_id_from_der(der_a) != hello_a.get("id"):
            raise ValueError("peer id does not match its certificate")
        na = b64d(hello_a["nonce"])
        strong = method == "qr"
        key = pair_key(secret.encode(), na + nb, strong)
        transcript = pair_transcript(na, nb, der_a, daemon.identity.der)
        # Prove we know the code as the client, then require a *different*,
        # role-bound proof from the server before pinning anything. Comparing
        # the server's reply against the value we just sent would let a rogue
        # server reflect it and be trusted without knowing the code.
        client_proof = pair_proof(key, "client", transcript)
        await send_json(writer, {"t": "pair.confirm", "mac": b64e(client_proof)})
        reply = await recv_json(reader)
        if reply.get("t") == "pair.error":
            raise ValueError("wrong pairing code")
        if reply.get("t") != "pair.confirm":
            raise ValueError("unexpected pairing reply")
        server_proof = pair_proof(key, "server", transcript)
        if not hmac.compare_digest(server_proof, b64d(reply.get("mac", ""))):
            raise ValueError("server failed to prove knowledge of the pairing code")
        done = await recv_json(reader)
        if done.get("t") != "pair.done":
            raise ValueError("pairing did not complete")
        peer = daemon.store.add(
            id_=hello_a.get("id", ""),
            name=hello_a.get("name", ""),
            cert_pem=der_to_pem(der_a),
            addresses=[host],
            port=int(hello_a.get("port", TCP_PORT)),
        )
        await daemon.peers_changed()
        log(f"paired with {peer['name']} ({peer['id']})")
        return {"ok": True, "peer": public_peer(peer)}
    finally:
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()


# --------------------------------------------------------------------------- #
# framing
# --------------------------------------------------------------------------- #

async def send_json(writer: asyncio.StreamWriter, obj: dict) -> None:
    writer.write(json.dumps(obj, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def recv_json(reader: asyncio.StreamReader, timeout: float = 15.0) -> dict:
    line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
    return json.loads(line.decode())


def public_peer(peer: dict) -> dict:
    return {
        "id": peer["id"],
        "name": peer["name"],
        "enabled": bool(peer.get("enabled", True)),
        "addresses": peer.get("addresses", []),
        "port": peer.get("port", TCP_PORT),
        "fingerprint": peer.get("fp", ""),
        "paired_at": peer.get("paired_at", 0),
    }


# --------------------------------------------------------------------------- #
# the daemon
# --------------------------------------------------------------------------- #

class Daemon:
    def __init__(self, state_dir: Path, socket_path: Path, *, install_hook: bool = True,
                 port: int = TCP_PORT, discovery_port: int = DISCOVERY_PORT,
                 bind_loopback: bool = False):
        self.state_dir = state_dir
        self.socket_path = socket_path
        self.install_hook = install_hook
        self.port = int(port)
        self.discovery_port = int(discovery_port)
        self.bind_loopback = bool(bind_loopback)
        self.identity = Identity(state_dir)
        self.store_bundle = state_dir / "trust.pem"
        self.store = PeerStore(state_dir)
        self.themes = ThemeManager()
        self.discovered: dict[str, dict] = {}
        self.clients: set[asyncio.StreamWriter] = set()
        self.pairing: PairingServer | None = None
        self._command_servers: list[asyncio.AbstractServer] = []
        self._command_bundle_fp = ""
        self._started = False
        self._unix_server: asyncio.AbstractServer | None = None
        self._discovery_transport: asyncio.DatagramTransport | None = None
        self._beacon_task: asyncio.Task | None = None
        self._suppress_theme = ""
        self._suppress_until = 0.0
        self._wallpaper_task: asyncio.Task | None = None
        self._wallpaper_sig: tuple = ()
        self._wallpaper_suppress_path = ""
        self._wallpaper_suppress_until = 0.0
        self._run = True

    def bind_addresses(self) -> list[str]:
        """Addresses the command and pairing listeners bind to.

        Never the WAN: private/VPN addresses only, or loopback in test mode.
        """
        if self.bind_loopback:
            return ["127.0.0.1"]
        return [addr for addr, _ in local_ipv4_addresses()] or ["127.0.0.1"]

    # ---- state ---------------------------------------------------------- #
    def snapshot(self) -> dict:
        discovered = []
        for entry in self.discovered.values():
            if entry["last_seen"] + PEER_TTL < now():
                continue
            if any(p["id"] == entry["id"] for p in self.store.peers.values()):
                continue
            discovered.append({
                "id": entry["id"],
                "name": entry["name"],
                "address": entry["addr"],
                "port": entry["port"],
                "pair_port": entry.get("pair_port", 0),
                "last_seen": int(entry["last_seen"]),
            })
        pairing = None
        if self.pairing and self.pairing.active:
            addresses = self.identity.address_list()
            host = addresses[0] if addresses else "127.0.0.1"
            qr = (f"everytheme://pair?v={PROTOCOL_VERSION}&id={self.identity.id}"
                  f"&name={self.identity.name}&host={host}&port={self.pairing.port}"
                  f"&token={self.pairing.token}")
            pairing = {
                "code": self.pairing.code,
                "token": self.pairing.token,
                "port": self.pairing.port,
                "expires": int(self.pairing.expires),
                "qr": qr,
            }
        return {
            "identity": {
                "id": self.identity.id,
                "name": self.identity.name,
                "fingerprint": self.identity.fingerprint,
                "addresses": self.identity.address_list(),
                "port": self.port,
            },
            "theme": self.themes.current(),
            "peers": [public_peer(p) for p in self.store.peers.values()],
            "discovered": discovered,
            "pairing": pairing,
        }

    def note_discovery(self, peer_id: str, name: str, addr: str, port: int, pair_port: int) -> None:
        entry = self.discovered.get(peer_id)
        is_new = entry is None
        if entry is None:
            entry = {"id": peer_id, "name": name, "addr": addr, "port": port,
                     "pair_port": pair_port, "last_seen": now()}
            self.discovered[peer_id] = entry
        # The pairing port is only open during a short window and changes every
        # time. Push state whenever anything the UI acts on changes, or the
        # "Pair" button will connect to a stale (closed) port.
        changed = is_new or (
            entry.get("name"), entry.get("addr"), entry.get("port"), entry.get("pair_port")
        ) != (name, addr, port, pair_port)
        entry.update({"name": name, "addr": addr, "port": port,
                      "pair_port": pair_port, "last_seen": now()})
        self.store.touch_endpoint(peer_id, [addr], port)
        if changed:
            log(f"discovered {name} at {addr}:{port}" + (f" pairing={pair_port}" if pair_port else ""))
            self.push_state()

    async def peers_changed(self) -> None:
        # The command listener verifies client certs against the pinned bundle,
        # so it must be rebuilt whenever a peer is added (to trust it) or
        # removed (to revoke it). Rebuilding before the caller returns means a
        # freshly paired device is reachable immediately, and a removed one is
        # cut off without a restart.
        self.push_state()
        await self._refresh_command_servers()

    def _bundle_fingerprint(self) -> str:
        try:
            return hashlib.sha256(self.store_bundle.read_bytes()).hexdigest()
        except OSError:
            return ""

    async def _start_command_servers(self) -> None:
        ctx = server_context(self.identity, self.store_bundle, verify_peers=True)
        for addr in self.bind_addresses():
            try:
                server = await asyncio.start_server(self._accept_command, host=addr,
                                                    port=self.port, ssl=ctx)
                self._command_servers.append(server)
                log(f"command listener on {addr}:{self.port}")
            except OSError as exc:
                log(f"could not bind {addr}:{self.port}: {exc}")

    async def _refresh_command_servers(self) -> None:
        fingerprint = self._bundle_fingerprint()
        # The in-process self-test never starts listeners; just track the bundle.
        if not self._started:
            self._command_bundle_fp = fingerprint
            return
        if fingerprint == self._command_bundle_fp and self._command_servers:
            return
        for server in self._command_servers:
            server.close()
        for server in self._command_servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        self._command_servers = []
        await self._start_command_servers()
        self._command_bundle_fp = fingerprint

    # ---- unix socket RPC for the shell plugin --------------------------- #
    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.clients.add(writer)
        try:
            await self._event(writer, "state", self.snapshot())
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    req = json.loads(line.decode())
                except ValueError:
                    continue
                asyncio.create_task(self._dispatch(req, writer))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self.clients.discard(writer)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _event(self, writer: asyncio.StreamWriter, name: str, data) -> None:
        with contextlib.suppress(Exception):
            await send_json(writer, {"event": name, "data": data})

    def push_state(self) -> None:
        for writer in list(self.clients):
            asyncio.create_task(self._event(writer, "state", self.snapshot()))

    async def _dispatch(self, req: dict, writer: asyncio.StreamWriter) -> None:
        rid = req.get("id")
        cmd = req.get("cmd", "")
        args = req.get("args") or {}
        try:
            data = await self._command(cmd, args)
            await send_json(writer, {"id": rid, "ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            await send_json(writer, {"id": rid, "ok": False, "error": str(exc)})

    async def _command(self, cmd: str, args: dict):
        if cmd == "status":
            return self.snapshot()
        if cmd == "pair.start":
            await self._pair_start()
            return self.snapshot()["pairing"]
        if cmd == "pair.cancel":
            await self._pair_cancel()
            return {"ok": True}
        if cmd == "pair.accept":
            host = str(args.get("host", "")).strip()
            port = int(args.get("port", 0) or 0)
            # A discovered peer's pairing port is short-lived and changes each
            # window, so resolve it from the live table rather than trusting a
            # value the UI may have cached.
            peer_id = str(args.get("id", ""))
            entry = self.discovered.get(peer_id) if peer_id else None
            if entry is not None:
                if not entry.get("pair_port"):
                    raise ValueError("the other device isn't showing a pairing code right now")
                host = entry["addr"]
                port = int(entry["pair_port"])
            if not host or not port:
                raise ValueError("no pairing address — start 'Pair a new device' on the other side")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass  # a hostname (e.g. a VPN's MagicDNS name); DNS decides
            else:
                if not is_local_source(host):
                    raise ValueError("refusing to pair with a non-local address")
            if args.get("token"):
                result = await run_pairing_client(self, host, port, "qr", str(args["token"]))
            else:
                result = await run_pairing_client(self, host, port, "code", str(args["code"]))
            self.push_state()
            return result
        if cmd == "peer.remove":
            removed = self.store.remove(str(args["id"]))
            await self.peers_changed()
            return {"removed": removed}
        if cmd == "peer.enabled":
            ok = self.store.set_enabled(str(args["id"]), bool(args["enabled"]))
            self.push_state()
            return {"ok": ok}
        if cmd == "theme.set":
            theme = str(args["theme"])
            if theme not in self.themes.available():
                raise ValueError(f"unknown theme: {theme}")
            self._apply_local(theme)
            asyncio.create_task(self._broadcast_theme(theme))
            return {"theme": theme}
        if cmd == "theme.local":
            theme = str(args["theme"])
            if self._is_suppressed(theme):
                return {"suppressed": True}
            if theme in self.themes.available():
                asyncio.create_task(self._broadcast_theme(theme))
            return {"theme": theme}
        raise ValueError(f"unknown command: {cmd}")

    def _is_suppressed(self, theme: str) -> bool:
        if now() < self._suppress_until and theme == self._suppress_theme:
            self._suppress_until = 0.0
            return True
        return False

    def _apply_local(self, theme: str) -> None:
        if theme == self.themes.current():
            return
        self.themes.apply(theme)

    async def _pair_start(self) -> None:
        await self._pair_cancel()
        self.pairing = PairingServer(self)
        await self.pairing.start()
        self._beacon_burst()
        self.push_state()

    async def _pair_cancel(self) -> None:
        if self.pairing is not None:
            await self.pairing.close()
            self.pairing = None
            self.push_state()

    # ---- authenticated command channel ---------------------------------- #
    async def _accept_command(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        try:
            sslobj = writer.get_extra_info("ssl_object")
            if sslobj is None:
                return
            der = sslobj.getpeercert(binary_form=True)
            if not der:
                return
            fp = cert_fingerprint(der)
            peer = self.store.by_fp(fp)
            if peer is None:
                log("rejected command from unpinned certificate")
                return
            peername = writer.get_extra_info("peername")
            if peername and not is_local_source(peername[0]):
                log(f"rejected command from non-local source {peername[0]}")
                return
            msg = await recv_json(reader)
            blob = None
            if msg.get("type") == "wallpaper.set":
                # Read the declared number of bytes *after* the header, with a
                # hard cap so a trusted-but-hostile peer cannot make us buffer
                # an unbounded payload.
                size = int((msg.get("payload") or {}).get("size", 0) or 0)
                if size < 1 or size > WALLPAPER_MAX_BYTES:
                    await send_json(writer, {"ok": False, "error": "wallpaper-size"})
                    return
                blob = await asyncio.wait_for(reader.readexactly(size), timeout=60.0)
            result = self._handle_message(peer, msg, blob)
            await send_json(writer, {"ok": result[0], "error": result[1]})
        except (asyncio.IncompleteReadError, ConnectionError, ValueError, KeyError) as exc:
            log(f"command error: {exc!r}")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    def _handle_message(self, peer: dict, msg: dict, blob: bytes | None = None) -> tuple[bool, str]:
        if msg.get("to") != self.identity.id:
            return False, "not-addressed-to-me"
        if msg.get("from") != peer["id"]:
            return False, "from-mismatch"
        mtype = msg.get("type")
        if mtype not in ALLOWED_COMMANDS:
            return False, "command-not-allowed"
        try:
            seq = int(msg.get("seq", 0))
            ts = float(msg.get("ts", 0))
        except (TypeError, ValueError):
            return False, "bad-header"
        if seq <= int(peer.get("last_seq", 0)):
            return False, "replay"
        if abs(now() - ts) > TS_WINDOW:
            return False, "stale-timestamp"
        if mtype == "theme.set":
            theme = str((msg.get("payload") or {}).get("theme", ""))
            if theme not in self.themes.available():
                return False, "unknown-theme"
            self._suppress_theme = theme
            self._suppress_until = now() + APPLY_SUPPRESS
            self.themes.apply(theme)
            self.push_state()
            log(f"applied remote theme {theme!r} from {peer['name']}")
        elif mtype == "wallpaper.ref":
            payload = msg.get("payload") or {}
            slug = str(payload.get("theme", ""))
            name = str(payload.get("name", ""))
            path = self.themes.resolve_theme_background(slug, name)
            if not path:
                return False, "background-not-found"
            self._apply_remote_wallpaper(path)
            log(f"applied remote theme wallpaper {slug}/{name} from {peer['name']}")
        elif mtype == "wallpaper.set":
            if not blob:
                return False, "missing-image"
            path = self._store_wallpaper(blob)
            if not path:
                return False, "not-an-image"
            self._apply_remote_wallpaper(path)
            log(f"applied remote wallpaper from {peer['name']}")
        peer["last_seq"] = seq
        self.store.save()
        return True, ""

    def _apply_remote_wallpaper(self, path: str) -> None:
        # Applying changes the background symlink, which our watcher would
        # otherwise re-broadcast as if the user had picked it locally.
        self._wallpaper_suppress_path = os.path.realpath(path)
        self._wallpaper_suppress_until = now() + WALLPAPER_SUPPRESS
        self.themes.set_background(path)
        self._wallpaper_sig = self._wallpaper_signature()
        self.push_state()

    def _store_wallpaper(self, blob: bytes) -> str:
        ext = detect_image_ext(blob)
        if ext is None:
            return ""
        digest = hashlib.sha256(blob).hexdigest()[:32]
        directory = self.state_dir / "wallpapers"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = directory / f"{digest}{ext}"
        if not target.exists():
            atomic_write(target, blob, 0o644)
        return str(target)

    async def _broadcast_theme(self, theme: str) -> None:
        targets = [p for p in self.store.peers.values() if p.get("enabled", True)]
        await asyncio.gather(*(self._send_theme(p, theme) for p in targets),
                             return_exceptions=True)
        self.push_state()

    async def _send_command(self, peer: dict, mtype: str, payload: dict,
                            blob: bytes | None = None) -> bool:
        addresses = self._peer_addresses(peer)
        if not addresses:
            return False
        ctx = client_context(self.identity, self.store_bundle, verify_server=True)
        peer["out_seq"] = int(peer.get("out_seq", 0)) + 1
        msg = {
            "v": PROTOCOL_VERSION,
            "from": self.identity.id,
            "to": peer["id"],
            "seq": peer["out_seq"],
            "ts": now(),
            "type": mtype,
            "payload": payload,
        }
        # A peer may be mid-restart or rebuilding its listener; retry briefly.
        for attempt in range(3):
            for host in addresses[:4]:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host=host,
                                                port=int(peer.get("port", self.port)),
                                                ssl=ctx, server_hostname="everytheme"),
                        timeout=CONNECT_TIMEOUT)
                    await send_json(writer, msg)
                    if blob is not None:
                        writer.write(blob)
                        await writer.drain()
                    reply = await recv_json(reader, timeout=30.0)
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    if reply.get("ok"):
                        self.store.save()
                        log(f"pushed {mtype} to {peer['name']} ({host})")
                        return True
                except (OSError, asyncio.TimeoutError, ConnectionError, ValueError):
                    continue
            if attempt < 2:
                await asyncio.sleep(0.4)
        log(f"could not reach peer {peer['name']} for {mtype}")
        return False

    async def _send_theme(self, peer: dict, theme: str) -> None:
        await self._send_command(peer, "theme.set", {"theme": theme})

    def _wallpaper_reference(self) -> dict | None:
        """A lightweight reference when the background belongs to the theme."""
        path = current_background_path()
        if not path:
            return None
        slug = self.themes.current()
        try:
            inside = os.path.commonpath([path, str(self.themes.current_theme_backgrounds())])
        except ValueError:
            return None
        if inside != str(self.themes.current_theme_backgrounds()):
            return None
        return {"theme": slug, "name": os.path.basename(path)}

    async def _broadcast_wallpaper(self) -> None:
        targets = [p for p in self.store.peers.values() if p.get("enabled", True)]
        await asyncio.gather(*(self._send_wallpaper(p) for p in targets),
                             return_exceptions=True)
        self.push_state()

    async def _send_wallpaper(self, peer: dict) -> None:
        ref = self._wallpaper_reference()
        if ref is not None:
            await self._send_command(peer, "wallpaper.ref", ref)
            return
        path = current_background_path()
        if not path:
            return
        try:
            data = Path(path).read_bytes()
        except OSError:
            return
        if len(data) > WALLPAPER_MAX_BYTES:
            log(f"wallpaper too large to sync ({len(data)} bytes)")
            return
        if detect_image_ext(data) is None:
            log(f"not a known image type, skipping {path!r}")
            return
        await self._send_command(peer, "wallpaper.set",
                                 {"size": len(data), "name": os.path.basename(path)},
                                 blob=data)

    # ---- local wallpaper watcher ---------------------------------------- #
    def _wallpaper_signature(self) -> tuple:
        path = current_background_path()
        if not path:
            return ()
        try:
            st = os.stat(path)
            return (path, st.st_size, int(st.st_mtime))
        except OSError:
            return ()

    def _wallpaper_suppressed(self) -> bool:
        if now() >= self._wallpaper_suppress_until:
            return False
        return current_background_path() == self._wallpaper_suppress_path

    async def _wallpaper_loop(self) -> None:
        self._wallpaper_sig = self._wallpaper_signature()
        while self._run:
            await asyncio.sleep(WALLPAPER_POLL)
            sig = self._wallpaper_signature()
            if sig == self._wallpaper_sig:
                continue
            self._wallpaper_sig = sig
            if not sig:
                continue
            if self._wallpaper_suppressed():
                self._wallpaper_suppress_until = 0.0
                continue
            asyncio.create_task(self._broadcast_wallpaper())

    def _peer_addresses(self, peer: dict) -> list[str]:
        addresses: list[str] = []
        entry = self.discovered.get(peer["id"])
        if entry:
            addresses.append(entry["addr"])
        addresses.extend(peer.get("addresses", []))
        return list(dict.fromkeys(a for a in addresses if is_local_source(a)))

    # ---- discovery beacons ---------------------------------------------- #
    def _beacon_payload(self) -> bytes:
        pair_port = self.pairing.port if (self.pairing and self.pairing.active) else 0
        return json.dumps({
            "everytheme": PROTOCOL_VERSION,
            "id": self.identity.id,
            "name": self.identity.name,
            "port": self.port,
            "pair": pair_port,
            "ts": int(now()),
        }, separators=(",", ":")).encode()

    def _beacon_burst(self) -> None:
        if not self._discovery_transport:
            return
        payload = self._beacon_payload()
        targets: set[str] = set()
        if not self.bind_loopback:
            targets.add("255.255.255.255")
            for addr, prefixlen in local_ipv4_addresses():
                with contextlib.suppress(ValueError):
                    targets.add(broadcast_address(addr, prefixlen))
        for peer in self.store.peers.values():
            targets.update(peer.get("addresses", []))
        for target in targets:
            with contextlib.suppress(OSError):
                self._discovery_transport.sendto(payload, (target, self.discovery_port))

    def _expire_discovered(self) -> None:
        stale = [pid for pid, entry in self.discovered.items()
                 if entry["last_seen"] + PEER_TTL < now()]
        if stale:
            for pid in stale:
                del self.discovered[pid]
            self.push_state()

    async def _beacon_loop(self) -> None:
        while self._run:
            self._beacon_burst()
            self._expire_discovered()
            await asyncio.sleep(BEACON_INTERVAL)

    # ---- startup --------------------------------------------------------- #
    async def start(self) -> None:
        self._started = True
        # Command listeners are bound per private address; never 0.0.0.0.
        await self._refresh_command_servers()

        # Unix socket for the shell plugin.
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)
        self._unix_server = await asyncio.start_unix_server(self._client,
                                                            path=str(self.socket_path))
        os.chmod(self.socket_path, 0o600)

        # Discovery.
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DiscoveryProtocol(self),
            local_addr=("127.0.0.1" if self.bind_loopback else "0.0.0.0", self.discovery_port),
            reuse_port=True,
        )
        self._discovery_transport = transport

        if self.install_hook:
            self.install_theme_hook()
        self._beacon_task = asyncio.create_task(self._beacon_loop())
        self._wallpaper_task = asyncio.create_task(self._wallpaper_loop())
        self._beacon_burst()
        log(f"everytheme daemon up as {self.identity.name} ({self.identity.id})")

    async def stop(self) -> None:
        self._run = False
        if self._beacon_task:
            self._beacon_task.cancel()
        if self._wallpaper_task:
            self._wallpaper_task.cancel()
        await self._pair_cancel()
        if self._unix_server:
            self._unix_server.close()
            with contextlib.suppress(Exception):
                await self._unix_server.wait_closed()
        for server in self._command_servers:
            server.close()
        for server in self._command_servers:
            with contextlib.suppress(Exception):
                await server.wait_closed()
        if self._discovery_transport:
            self._discovery_transport.close()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.socket_path)

    # ---- theme-set hook -------------------------------------------------- #
    def install_theme_hook(self) -> None:
        """Install a theme-set hook so *any* local theme change is broadcast."""
        hook_dir = Path.home() / ".config" / "omarchy" / "hooks" / "theme-set.d"
        try:
            hook_dir.mkdir(parents=True, exist_ok=True)
            script = hook_dir / "50-everytheme"
            helper = Path(__file__).resolve()
            content = (
                "#!/bin/bash\n"
                "# Installed by the EveryTheme plugin. Broadcasts local theme changes.\n"
                f'exec "{sys.executable}" "{helper}"'
                f' --state-dir "{self.state_dir}" --socket "{self.socket_path}"'
                ' notify-theme "$1"\n'
            )
            if not script.exists() or script.read_text() != content:
                atomic_write(script, content.encode(), 0o755)
        except OSError as exc:
            log(f"could not install theme hook: {exc}")


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #

def default_socket_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.path.isdir(runtime):
        runtime = tempfile.gettempdir()
    return Path(runtime) / "everytheme.sock"


async def socket_is_live(path: Path) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), timeout=1.0)
    except (OSError, asyncio.TimeoutError):
        return False
    with contextlib.suppress(Exception):
        await send_json(writer, {"id": 0, "cmd": "status", "args": {}})
        await recv_json(reader)
    writer.close()
    return True


async def rpc_once(socket_path: Path, cmd: str, args: dict) -> dict:
    reader, writer = await asyncio.open_unix_connection(str(socket_path))
    try:
        await send_json(writer, {"id": 1, "cmd": cmd, "args": args})
        while True:
            msg = await recv_json(reader)
            if "event" in msg:
                continue
            return msg
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def run_daemon(state_dir: Path, socket_path: Path, *, install_hook: bool = True,
                     port: int = TCP_PORT, discovery_port: int = DISCOVERY_PORT,
                     bind_loopback: bool = False) -> None:
    # A single daemon per machine. The bar mounts one widget per monitor, each
    # of which spawns this process; a non-blocking lock makes the losers exit
    # before they can clobber the socket or race identity generation.
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(state_dir / ".daemon.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("daemon already running; exiting")
        os.close(lock_fd)
        return

    try:
        if await socket_is_live(socket_path):
            log("daemon already running; exiting")
            return
        daemon = Daemon(state_dir, socket_path, install_hook=install_hook, port=port,
                        discovery_port=discovery_port, bind_loopback=bind_loopback)
        await daemon.start()
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        await daemon.stop()
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="everytheme-helper")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--socket", default=str(default_socket_path()))
    parser.add_argument("--no-hook", action="store_true",
                        help="do not install the theme-set hook (testing)")
    parser.add_argument("--port", type=int, default=TCP_PORT,
                        help=f"command listener port (default {TCP_PORT})")
    parser.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT,
                        help=f"discovery port (default {DISCOVERY_PORT})")
    parser.add_argument("--bind-loopback", action="store_true",
                        help="bind loopback only (for running two instances on one host)")
    sub = parser.add_subparsers(dest="mode")

    sub.add_parser("daemon")
    notify = sub.add_parser("notify-theme")
    notify.add_argument("theme")
    sub.add_parser("status")
    sub.add_parser("selftest")

    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir)
    socket_path = Path(args.socket)
    mode = args.mode or "daemon"

    if mode == "daemon":
        asyncio.run(run_daemon(state_dir, socket_path, install_hook=not args.no_hook,
                               port=args.port, discovery_port=args.discovery_port,
                               bind_loopback=args.bind_loopback))
        return 0

    if mode == "notify-theme":
        try:
            asyncio.run(_notify(socket_path, {"cmd": "theme.local", "args": {"theme": args.theme}}))
        except OSError:
            # Daemon is not running; nothing to sync.
            pass
        return 0

    if mode == "status":
        try:
            reply = asyncio.run(rpc_once(socket_path, "status", {}))
            print(json.dumps(reply.get("data", reply), indent=2))
            return 0
        except OSError:
            print(json.dumps({"error": "daemon not running"}))
            return 1

    if mode == "selftest":
        from everytheme_selftest import run_selftest
        return run_selftest(state_dir)

    parser.error(f"unknown mode: {mode}")
    return 2


async def _notify(socket_path: Path, payload: dict) -> None:
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(socket_path)), timeout=2.0)
    try:
        await send_json(writer, {"id": 1, **payload})
        with contextlib.suppress(Exception):
            await recv_json(reader)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


if __name__ == "__main__":
    raise SystemExit(main())
