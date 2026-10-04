#!/usr/bin/env python3
"""End-to-end security self-test for the EveryTheme helper.

Exercises the properties the design depends on, with no real network binding
beyond loopback:

1. Two devices pair successfully with the correct code, pinning each other.
2. A wrong pairing code is rejected and pins nothing.
3. A rogue server that echoes the client's proof back to it is rejected and
   never pinned (the reflection attack the marketplace review flagged).
4. A paired peer can send an authenticated command.
5. A replayed command is rejected.
6. A device holding a valid-looking but unpinned certificate is rejected at
   the mutual-TLS layer before any command is read.

Run: python3 helper/everytheme_helper.py --state-dir /tmp/et-selftest selftest
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import tempfile
from pathlib import Path

import everytheme_helper as H

HOST = "127.0.0.1"


class Device:
    def __init__(self, root: Path, name: str):
        self.dir = root / name
        self.daemon = H.Daemon(self.dir, self.dir / "test.sock")

    async def open_pairing(self):
        self.daemon.pairing = H.PairingServer(self.daemon)
        await self.daemon.pairing.start(hosts=[HOST])
        return self.daemon.pairing

    async def close_pairing(self):
        with contextlib.suppress(Exception):
            await self.daemon.pairing.close()
        self.daemon.pairing = None


async def pair(initiator: Device, acceptor: Device, *, method: str, secret: str | None = None) -> None:
    pairing = await initiator.open_pairing()
    try:
        await H.run_pairing_client(acceptor.daemon, HOST, pairing.port, method,
                                   pairing.code if secret is None else secret)
    finally:
        await initiator.close_pairing()


async def echo_attack(attacker: Device, victim: Device) -> bool:
    """A rogue pairing server that reflects the client's own proof back at it.

    Returns True only if the client was fooled into pinning the attacker. It
    never knows the pairing code, so a correct handshake must reject it.
    """
    ctx = H.server_context(attacker.daemon.identity, attacker.daemon.store_bundle,
                           verify_peers=False)

    async def handle(reader, writer):
        try:
            hello_b = await H.recv_json(reader)
            if hello_b.get("t") != "pair.hello":
                return
            na = secrets.token_bytes(16)
            await H.send_json(writer, {
                "t": "pair.hello",
                "v": H.PROTOCOL_VERSION,
                "id": attacker.daemon.identity.id,
                "name": attacker.daemon.identity.name,
                "nonce": H.b64e(na),
                "cert": H.b64e(attacker.daemon.identity.der),
                "port": attacker.daemon.port,
            })
            confirm = await H.recv_json(reader)
            # Reflect the client's proof straight back as our "proof".
            await H.send_json(writer, {"t": "pair.confirm", "mac": confirm.get("mac")})
            await H.send_json(writer, {"t": "pair.done", "id": attacker.daemon.identity.id})
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    server = await asyncio.start_server(handle, host=HOST, port=0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        await H.run_pairing_client(victim.daemon, HOST, port, "code", "424242")
        return len(victim.daemon.store.peers) > 0, "completed"
    except ValueError as exc:
        return False, str(exc)
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


async def run() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, bool(ok), detail))

    with tempfile.TemporaryDirectory(prefix="everytheme-selftest-") as tmp:
        root = Path(tmp)
        a = Device(root, "a")
        b = Device(root, "b")
        c = Device(root, "c")  # stays unpinned, for the negative TLS test
        d = Device(root, "d")  # pairs via the QR/token path

        # 1. Successful pairing with the correct one-time code.
        await pair(a, b, method="code")
        a_peers = list(a.daemon.store.peers.values())
        b_peers = list(b.daemon.store.peers.values())
        check("pair: both sides pinned", len(a_peers) == 1 and len(b_peers) == 1,
              f"a={len(a_peers)} b={len(b_peers)}")
        check("pair: fingerprints agree",
              bool(a_peers and b_peers)
              and a_peers[0]["fp"] == b.daemon.identity.fingerprint
              and b_peers[0]["fp"] == a.daemon.identity.fingerprint)

        # 2. Wrong code must fail and pin nothing.
        before = len(b.daemon.store.peers)
        pairing = await a.open_pairing()
        wrong = "000000" if pairing.code != "000000" else "111111"
        try:
            await H.run_pairing_client(b.daemon, HOST, pairing.port, "code", wrong)
            wrong_rejected = False
        except ValueError:
            wrong_rejected = True
        finally:
            await a.close_pairing()
        check("pair: wrong code rejected",
              wrong_rejected and len(b.daemon.store.peers) == before,
              f"rejected={wrong_rejected} peers={len(b.daemon.store.peers)}")

        # 3. QR/token pairing path (no typed code) — used by manual links.
        pairing = await a.open_pairing()
        try:
            await H.run_pairing_client(d.daemon, HOST, pairing.port, "qr", pairing.token)
        finally:
            await a.close_pairing()
        check("pair: qr token path", len(d.daemon.store.peers) == 1,
              f"d={len(d.daemon.store.peers)}")

        # 4. Reflection attack: a rogue server that echoes the client's own
        #    proof back must not be pinned. This is the flaw that the generic
        #    "confirm == the MAC we sent" check allowed before role binding.
        victim = Device(root, "e")
        rogue = Device(root, "rogue")
        fooled, reason = await echo_attack(rogue, victim)
        check("pair: reflected server proof rejected", not fooled, reason)
        check("pair: rejection is the server-proof step", "prove" in reason, reason)
        check("pair: rogue certificate not pinned",
              len(victim.daemon.store.peers) == 0,
              f"peers={len(victim.daemon.store.peers)}")

        # 5 + 6. Authenticated command channel and replay rejection.
        a_ctx = H.server_context(a.daemon.identity, a.daemon.store_bundle, verify_peers=True)
        server = await asyncio.start_server(a.daemon._accept_command, host=HOST, port=0, ssl=a_ctx)
        port = server.sockets[0].getsockname()[1]

        async def send(client_ctx, msg) -> dict:
            reader, writer = await asyncio.open_connection(HOST, port, ssl=client_ctx,
                                                           server_hostname="everytheme")
            try:
                await H.send_json(writer, msg)
                return await H.recv_json(reader)
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        def ping(seq: int) -> dict:
            return {"v": 1, "from": b.daemon.identity.id, "to": a.daemon.identity.id,
                    "seq": seq, "ts": H.now(), "type": "ping", "payload": {}}

        b_ctx = H.client_context(b.daemon.identity, b.daemon.store_bundle, verify_server=True)
        first = await send(b_ctx, ping(1))
        check("command: paired peer accepted", first.get("ok") is True, str(first))
        replay = await send(b_ctx, ping(1))
        check("command: replay rejected",
              replay.get("ok") is False and replay.get("error") == "replay", str(replay))

        # 5. Unpinned certificate rejected at TLS.
        c_ctx = H.client_context(c.daemon.identity, a.daemon.store_bundle, verify_server=True)
        try:
            await send(c_ctx, ping(2))
            check("command: unpinned cert rejected", False, "connection succeeded")
        except Exception as exc:  # noqa: BLE001
            check("command: unpinned cert rejected", True, type(exc).__name__)

        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()

    return results


def run_selftest(state_dir: Path) -> int:
    results = asyncio.run(run())
    ok = True
    for name, passed, detail in results:
        mark = "PASS" if passed else "FAIL"
        line = f"[{mark}] {name}"
        if detail and not passed:
            line += f"  ({detail})"
        print(line)
        ok = ok and passed
    print("\nSELFTEST", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(run_selftest(Path(tempfile.gettempdir()) / "everytheme-selftest"))
