# EveryTheme

Keep the Omarchy theme on all of **your own** machines in sync.

EveryTheme puts a swatch icon on the Quickshell bar. Click it to see the
devices you have paired, flip a per-device switch to exclude one temporarily,
and pair new machines. Change the theme on any paired machine and every other
paired machine follows.

EveryTheme also syncs wallpapers: pick a photo on one machine and the others
follow. A background that belongs to the active theme is sent as a tiny
reference (the receivers already have the file, because themes sync); a custom
image is transferred over the authenticated channel, size-capped and validated.

Devices must be reachable over your LAN or a VPN. EveryTheme deliberately does
**not** expose anything to the internet and does not punch through NAT — an
attacker who knows your WAN IP cannot add themselves as a device or push theme
or wallpaper changes.

```
┌─ EveryTheme bar widget (QML) ─┐  Unix socket, JSON  ┌─ everytheme-helper ─┐
│ icon · device menu · switches │ ◀─────────────────▶ │ discovery (UDP)     │
└───────────────────────────────┘                     │ mutual TLS (1.3)    │
                                                      │ paired Ed25519 IDs  │
                                                      └─────────┬───────────┘
                                                                │ omarchy theme set
                                                      ┌─────────▼───────────┐
                                                      │ theme-set hook       │
                                                      └─────────────────────┘
```

---

## Install

From the Omarchy plugin marketplace, or:

```bash
omarchy plugin add https://github.com/signaldirective/everytheme.git --enable
```

The helper needs only the Python standard library and the `openssl` binary,
both already present on Omarchy. No `pip install`, no sudo, no systemd unit.

---

## How it works

| Piece | Responsibility |
|---|---|
| `BarWidget.qml` | Bar icon, spawns/supervises the helper, keeps a Unix-socket JSON-RPC connection, opens the menu |
| `Panel.qml` | Device list, per-device switches, pairing UI |
| `helper/everytheme_helper.py` | Device identity, LAN discovery, pairing handshake, authenticated command channel, applying and broadcasting themes and wallpapers |
| theme-set hook | `~/.config/omarchy/hooks/theme-set.d/50-everytheme` — installed by the helper so *any* local theme change (keybind, CLI, another app) is broadcast |
| background watcher | Polls `~/.local/state/omarchy/current/background` (Omarchy has no background hook) and broadcasts changes, with loop suppression |

The helper listens on a private/LAN address and on a Unix socket, and speaks
newline-delimited JSON with the UI.

### Wallpaper sync

- If the new background lives under the current theme's `backgrounds/`
  directory, the helper sends `wallpaper.ref {theme, name}`; the receiver
  resolves its own copy (themes are already in sync) and applies it. No image
  bytes cross the network.
- Otherwise (a custom image you picked), the helper sends `wallpaper.set`:
  a JSON header followed by the raw bytes. The receiver enforces a 25 MB cap,
  checks the image magic bytes, stores it under
  `~/.config/omarchy/everytheme/wallpapers/`, and applies it.
- Applying a wallpaper changes the same symlink the watcher observes, so a
  suppression window prevents a received wallpaper from being re-broadcast.

---

## Security model

The design starts from one observation: **being on a network is not a secret**,
and it is not authentication. Everyone on a LAN or VPN shares it. So the problem
is split into three independent questions:

1. **Can a peer reach me?** — *network scope*
2. **Who is it?** — *cryptographic identity*
3. **Did I approve it?** — *explicit pairing*

### 1. Network scope (reachability)

- The command listener binds only to RFC1918 / link-local / IPv6 ULA
  addresses, plus the CGNAT range used by Tailscale (`100.64.0.0/10`). It never
  binds `0.0.0.0`, never port-forwards, and never uses UPnP/NAT-PMP.
- A source address is re-checked when a connection is accepted.
- Discovery uses UDP broadcast, which routers do not forward, so it is
  LAN-scoped by construction.

On its own this defeats the "someone knows my WAN IP" attack, but it is not
enough on a shared network. It is only the filter.

### 2. Cryptographic identity

Each device generates a self-signed **Ed25519** certificate on first run. Its
SHA-256 fingerprint *is* the device id. The command channel is **TLS 1.3 with
mutual authentication**: a peer must present a certificate that is pinned in
your trust store, or the TLS handshake is refused before a single command byte
is read. Commands are additionally checked for recipient, monotonic sequence
(replay), freshness, and an allowlist (`theme.set`, `ping` only), and theme
names are validated against the installed themes before being applied.

### 3. Explicit pairing (consent)

Trust is established once, out of band:

1. On device A, choose **Pair a new device**. A shows a 6-digit code (and a
   high-entropy pairing link/token) that expires after 2 minutes.
2. On device B, select A from *On your network* and enter the code (or scan the
   token).
3. The two devices run an ephemeral ECDH exchange bound to the code through an
   HKDF/HMAC confirmation, then each **pins the other's certificate**.

The code is the out-of-band channel. An attacker who can reach the pairing port
does not have it, and the pairing window is short, single-purpose, and limited
to a handful of attempts. The QR/token path uses 128 bits of entropy; the typed
6-digit path relies on the short TTL plus attempt limiting.

### Why a WAN-IP attacker fails

1. There is no port forward and the listener is not bound to a WAN address, so
   there is usually nothing to connect to.
2. Even if reachable, an unpaired certificate is rejected at the TLS layer.
3. Pairing requires the one-time code, which never crosses the network
   unwrapped.
4. Even a trusted peer can only invoke the allowlisted, validated theme command.

### Switch vs. trust

These are deliberately separate:

- **Trust** (paired or not) is security. Untrusted devices appear under *On your
  network* and cannot be switched on.
- **Sync enabled** (your switch) is a local, temporary mute. It is stored on
  your machine and is not a security boundary.

---

## Development

```bash
# Unit-level security tests: pairing, replay, unpinned-cert rejection
python3 helper/everytheme_helper.py --state-dir /tmp/et selftest

# Full two-device integration test, no second machine required.
# Spins up two real daemons on loopback with a fake `omarchy` on PATH, so your
# real theme is never touched. Covers pairing, propagation, the per-device
# switch, re-enable, and the theme-set hook path.
python3 helper/test_integration.py
EVERYTHEME_KEEP_DIR=/tmp/et-int python3 helper/test_integration.py  # keep logs

# Inspect a running daemon
python3 helper/everytheme_helper.py status

# Run a second daemon by hand on loopback with custom ports
python3 helper/everytheme_helper.py --state-dir /tmp/et --socket /tmp/et.sock \
  --port 45992 --discovery-port 45993 --bind-loopback --no-hook daemon
```

State lives in `~/.config/omarchy/everytheme/`:

```
identity/cert.pem · identity/key.pem   # this device's keypair (key is 0600)
peers.json                             # pinned devices
trust.pem                              # CA bundle rebuilt from pinned certs
```

---

## Limitations / roadmap

- QR codes are emitted as a `everytheme://` link, not rendered as an image yet;
  the 6-digit code path is fully usable.
- Discovery is UDP broadcast. Across a VPN that does not forward broadcast,
  add the peer manually (unicast beacons are still sent to known peers).
- Removing a device is local revocation: the removed device is dropped from the
  trust bundle, so it can no longer connect to you.
- Simultaneous theme changes on two devices will race; the last one applied
  wins.

## License

MIT — see [LICENSE](LICENSE).
