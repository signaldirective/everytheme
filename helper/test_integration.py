#!/usr/bin/env python3
"""Two real EveryTheme daemon processes on one machine, end to end.

We cannot assume a second Omarchy device exists, so this test simulates one:
it launches a second helper daemon on 127.0.0.1 with its own HOME, state
directory, and ports, then drives exactly the RPCs the bar UI sends. A fake
`omarchy` executable on PATH records `theme set` calls so the real desktop
theme is never modified.

Covers the full product path:
  * pair two devices with the one-time code
  * pair via a manual host+port+token (the "paste link" path, no discovery)
  * propagate a theme push A -> B
  * per-device switch excludes B from the next push
  * re-enabling resumes propagation
  * the installed theme-set hook broadcasts a local change (production path)

Run: python3 helper/test_integration.py
Set EVERYTHEME_KEEP_DIR=/some/dir to keep the sandbox and daemon logs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HELPER = Path(__file__).resolve().parent / "everytheme_helper.py"

OMARCHY_STUB = """#!/bin/bash
# Fake omarchy for tests: records calls and tracks "current" theme/background.
echo "$*" >> "$HOME/omarchy-calls.log"
case "$1 $2" in
  "theme set")
    mkdir -p "$HOME/.local/state/omarchy/current"
    printf '%s' "$3" > "$HOME/.local/state/omarchy/current/theme.name"
    ;;
  "theme current")
    cat "$HOME/.local/state/omarchy/current/theme.name" 2>/dev/null
    ;;
  "theme dir")
    echo "$HOME/.config/omarchy/themes/$3"
    ;;
  "theme bg")
    case "$3" in
      set)
        mkdir -p "$HOME/.local/state/omarchy/current"
        ln -nsf "$(realpath "$4")" "$HOME/.local/state/omarchy/current/background"
        ;;
      current)
        readlink -f "$HOME/.local/state/omarchy/current/background" 2>/dev/null
        ;;
    esac
    ;;
esac
exit 0
"""


class Device:
    def __init__(self, root: Path, name: str, port: int):
        self.name = name
        self.home = root / name
        (self.home / ".config" / "omarchy" / "themes").mkdir(parents=True)
        for theme in ("gruvbox", "catppuccin", "everforest", "nord"):
            (self.home / ".config" / "omarchy" / "themes" / theme).mkdir(exist_ok=True)
        self.state = self.home / "state"
        self.sock = root / f"{name}.sock"
        self.port = port
        self.discovery = port + 1
        self.proc: subprocess.Popen | None = None
        self.log = open(root / f"{name}.daemon.log", "w")
        self.bin_dir: Path | None = None

    def start(self, bin_dir: Path) -> None:
        self.bin_dir = bin_dir
        env = dict(os.environ)
        env["HOME"] = str(self.home)
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        self.proc = subprocess.Popen(
            [sys.executable, str(HELPER), "--state-dir", str(self.state),
             "--socket", str(self.sock), "--port", str(self.port),
             "--discovery-port", str(self.discovery), "--bind-loopback", "daemon"],
            env=env, stdout=self.log, stderr=self.log,
        )

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.proc.wait(timeout=5)
        with contextlib.suppress(Exception):
            self.log.close()

    def current_theme(self) -> str:
        path = self.home / ".local" / "state" / "omarchy" / "current" / "theme.name"
        try:
            return path.read_text().strip()
        except OSError:
            return ""

    def set_local_theme(self, theme: str) -> None:
        path = self.home / ".local" / "state" / "omarchy" / "current" / "theme.name"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(theme)

    def env(self) -> dict:
        return {**os.environ, "HOME": str(self.home),
                "PATH": f"{self.bin_dir}:{os.environ['PATH']}"}

    def run_omarchy(self, *args: str) -> None:
        subprocess.run([str(self.bin_dir / "omarchy"), *args], env=self.env(), check=False)

    def set_background(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"test")
        self.run_omarchy("theme", "bg", "set", str(path))

    def background(self) -> str:
        link = self.home / ".local" / "state" / "omarchy" / "current" / "background"
        try:
            return os.path.realpath(link)
        except OSError:
            return ""

    def omarchy_calls(self) -> list[str]:
        path = self.home / "omarchy-calls.log"
        try:
            return [line for line in path.read_text().splitlines() if line]
        except OSError:
            return []

    def hook_script(self) -> Path:
        return self.home / ".config" / "omarchy" / "hooks" / "theme-set.d" / "50-everytheme"


async def rpc(sock: Path, cmd: str, args: dict | None = None, timeout: float = 20.0) -> dict:
    reader, writer = await asyncio.open_unix_connection(str(sock))
    try:
        writer.write((json.dumps({"id": 1, "cmd": cmd, "args": args or {}}) + "\n").encode())
        await writer.drain()
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout)
            if not line:
                raise RuntimeError("daemon closed the socket")
            msg = json.loads(line)
            if "event" in msg:
                continue
            return msg
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def wait_for(predicate, timeout: float = 12.0, interval: float = 0.15) -> bool:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return predicate()


async def run() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, bool(ok), detail))

    keep = os.environ.get("EVERYTHEME_KEEP_DIR")
    cleanup = None
    if keep:
        root = Path(keep)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="everytheme-integration-")
        root = Path(cleanup.name)

    try:
        bin_dir = root / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "omarchy"
        stub.write_text(OMARCHY_STUB)
        stub.chmod(0o755)

        a = Device(root, "a", 45992)
        b = Device(root, "b", 46092)
        c = Device(root, "c", 46192)
        a.start(bin_dir)
        b.start(bin_dir)
        c.start(bin_dir)
        try:
            check("all daemons started",
                  await wait_for(lambda: a.sock.exists())
                  and await wait_for(lambda: b.sock.exists())
                  and await wait_for(lambda: c.sock.exists()))

            a_status = (await rpc(a.sock, "status")).get("data", {})
            b_status = (await rpc(b.sock, "status")).get("data", {})
            check("distinct identities",
                  a_status["identity"]["id"] != b_status["identity"]["id"])

            # --- pairing -------------------------------------------------- #
            pairing = (await rpc(a.sock, "pair.start")).get("data") or {}
            accept = await rpc(b.sock, "pair.accept",
                               {"host": "127.0.0.1", "port": pairing["port"],
                                "code": pairing["code"]})
            check("pair.accept ok", accept.get("ok") is True, str(accept))
            a_peers = (await rpc(a.sock, "status")).get("data", {}).get("peers", [])
            b_peers = (await rpc(b.sock, "status")).get("data", {}).get("peers", [])
            check("both devices pinned", len(a_peers) == 1 and len(b_peers) == 1,
                  f"a={len(a_peers)} b={len(b_peers)}")
            check("peer records command port",
                  bool(a_peers) and int(a_peers[0].get("port", 0)) == b.port,
                  str(a_peers[:1]))

            # --- theme propagation A -> B -------------------------------- #
            await rpc(a.sock, "theme.set", {"theme": "gruvbox"})
            check("theme applied on A", a.current_theme() == "gruvbox", a.current_theme())
            check("theme propagated to B",
                  await wait_for(lambda: b.current_theme() == "gruvbox"), b.current_theme())

            # --- per-device switch excludes B ---------------------------- #
            await rpc(a.sock, "peer.enabled", {"id": a_peers[0]["id"], "enabled": False})
            await rpc(a.sock, "theme.set", {"theme": "catppuccin"})
            check("A moved on", a.current_theme() == "catppuccin", a.current_theme())
            excluded = await wait_for(lambda: b.current_theme() == "catppuccin", timeout=1.5)
            check("switched-off device stays put", not excluded, b.current_theme())

            # --- re-enable resumes --------------------------------------- #
            await rpc(a.sock, "peer.enabled", {"id": a_peers[0]["id"], "enabled": True})
            await rpc(a.sock, "theme.set", {"theme": "everforest"})
            check("re-enabled device catches up",
                  await wait_for(lambda: b.current_theme() == "everforest"), b.current_theme())

            # --- manual pairing path: host + port + token, no discovery -- #
            pairing = (await rpc(a.sock, "pair.start")).get("data") or {}
            manual = await rpc(c.sock, "pair.accept",
                               {"host": "127.0.0.1", "port": pairing["port"],
                                "token": pairing["token"]})
            check("manual token pairing ok", manual.get("ok") is True, str(manual))
            c_peers = (await rpc(c.sock, "status")).get("data", {}).get("peers", [])
            check("manual pairing pinned", len(c_peers) == 1,
                  f"c={len(c_peers)}")

            # --- production hook path: local change broadcasts ----------- #
            hook = a.hook_script()
            check("theme-set hook installed", hook.exists(), str(hook))
            a.set_local_theme("nord")
            subprocess.run([str(hook), "nord"], check=False, env={
                **os.environ, "HOME": str(a.home),
                "PATH": f"{bin_dir}:{os.environ['PATH']}"})
            check("hook broadcast reaches B",
                  await wait_for(lambda: b.current_theme() == "nord"), b.current_theme())

            # --- custom wallpaper transfer A -> B ------------------------ #
            custom = a.home / "Pictures" / "custom.png"
            custom.parent.mkdir(parents=True, exist_ok=True)
            custom.write_bytes(b"\x89PNG\r\n\x1a\n" + b"everytheme" * 64)
            a.set_background(custom)
            check("custom wallpaper transferred to B",
                  await wait_for(lambda: "wallpapers" in b.background(), timeout=15),
                  b.background())

            # --- theme-background reference (no bytes on the wire) ------- #
            slug = a.current_theme()
            a_bg = (a.home / ".local" / "state" / "omarchy" / "current" / "theme"
                    / "backgrounds" / "bg1.png")
            a_bg.parent.mkdir(parents=True, exist_ok=True)
            a_bg.write_bytes(b"\x89PNG\r\n\x1a\n" + b"theme-bg")
            b_bg = b.home / ".config" / "omarchy" / "themes" / slug / "backgrounds" / "bg1.png"
            b_bg.parent.mkdir(parents=True, exist_ok=True)
            b_bg.write_bytes(b"\x89PNG\r\n\x1a\n" + b"theme-bg")
            a.set_background(a_bg)
            check("theme wallpaper reference applied on B",
                  await wait_for(lambda: b.background() == str(b_bg), timeout=15),
                  b.background())

            # --- no self-echo: A only set gruvbox once -------------------- #
            a_sets = [call for call in a.omarchy_calls() if call == "theme set gruvbox"]
            check("no echo loop on origin", len(a_sets) == 1, f"{len(a_sets)}x gruvbox")
        finally:
            a.stop()
            b.stop()
            c.stop()
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    return results


def main() -> int:
    results = asyncio.run(run())
    ok = True
    for name, passed, detail in results:
        mark = "PASS" if passed else "FAIL"
        line = f"[{mark}] {name}"
        if detail and not passed:
            line += f"  ({detail})"
        print(line)
        ok = ok and passed
    print("\nINTEGRATION", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
