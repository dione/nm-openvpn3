#!/usr/bin/env python3
"""
Read an OpenVPN .ovpn profile and emit an `nmcli connection add` command
that creates an nm-openvpn3 VPN connection.

Usage:
    scripts/ovpn-to-nmcli.py PROFILE.ovpn [--con-name NAME] [--apply] [--full-tunnel]

Behaviour:
- Stages the *verbatim* .ovpn under ~/.config/nm-openvpn3/<con-name>/profile.ovpn
  (mode 0600) and points the plugin at it via the `nm-openvpn3-profile`
  vpn.data key.  nm-openvpn3-service reads the file directly, so every
  OpenVPN option that openvpn3 understands (incl. tls-crypt-v2, peer-
  fingerprint, recent cipher/data-cipher syntax) round-trips losslessly.
- The remaining vpn.data values are cosmetic: NM/`nmcli connection show`
  display only.  We set `remote=<first>` and `connection-type=<tls|
  password|password-tls>` so the GUI does not look empty.
- With --full-tunnel, injects `redirect-gateway def1` into the staged
  profile (if not already present) so openvpn3 installs a 0.0.0.0/0
  route and NM promotes the VPN to the system default route.

Dry-run by default — pass --apply to actually create the directory,
write the file and run nmcli.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# Inline tags we recognise — used only to decide connection-type, NOT
# materialised to separate files (the raw .ovpn is shipped verbatim).
_INLINE_TAGS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")

# NM connection names are user-supplied; refuse path-traversal characters
# so we cannot write outside ~/.config/nm-openvpn3/.
_SAFE_CON_NAME = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9 ._-]{0,63}$")


def _validate_con_name(name: str) -> str:
    if not _SAFE_CON_NAME.match(name) or name in {".", ".."}:
        raise SystemExit(
            f"error: refusing unsafe con-name {name!r}; allowed chars are "
            f"[A-Za-z0-9 ._-], 1..64 chars, no '/'"
        )
    return name


def _summary(path: Path) -> dict[str, object]:
    """Light-touch scan of @path: collect remotes, detect TLS/password mode,
    note whether redirect-gateway is already present.  Used only to populate
    cosmetic vpn.data — full parsing happens inside openvpn3."""
    remotes: list[tuple[str, str | None, str | None]] = []
    has_cert_path = False
    has_inline_cert = False
    needs_password = False
    has_redirect_gateway = False

    in_block: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if in_block is not None:
            if line == f"</{in_block}>":
                in_block = None
            continue
        for tag in _INLINE_TAGS:
            if line == f"<{tag}>":
                in_block = tag
                if tag == "cert":
                    has_inline_cert = True
                break
        if in_block is not None:
            continue

        tokens = shlex.split(line, comments=False, posix=True)
        if not tokens:
            continue
        key = tokens[0]
        rest = tokens[1:]

        if key == "remote":
            host = rest[0] if rest else ""
            port = rest[1] if len(rest) > 1 else None
            proto = rest[2] if len(rest) > 2 else None
            entry = (host, port, proto)
            if entry not in remotes:
                remotes.append(entry)
        elif key == "cert":
            has_cert_path = True
        elif key == "auth-user-pass":
            needs_password = True
        elif key == "redirect-gateway":
            has_redirect_gateway = True

    return {
        "remotes": remotes,
        "has_cert": has_cert_path or has_inline_cert,
        "needs_password": needs_password,
        "has_redirect_gateway": has_redirect_gateway,
    }


def _connection_type(has_cert: bool, needs_password: bool) -> str | None:
    if has_cert and needs_password:
        return "password-tls"
    if has_cert:
        return "tls"
    if needs_password:
        return "password"
    return None


def _cosmetic_vpn_data(
    profile_path: Path,
    summary: dict[str, object],
) -> dict[str, str]:
    options: dict[str, str] = {"nm-openvpn3-profile": str(profile_path)}
    remotes = summary["remotes"]            # type: ignore[index]
    if remotes:
        host, port, proto = remotes[0]
        piece = host
        if port:
            piece += f":{port}"
        if proto:
            piece += f":{proto}"
        options["remote"] = piece
        if len(remotes) > 1:
            others = ", ".join(
                ":".join(str(x) for x in r if x is not None) for r in remotes[1:]
            )
            print(
                f"[info] multi-remote profile ({len(remotes)} entries); "
                f"vpn.data shows {piece}, openvpn3 receives all of them via "
                f"the raw profile.ovpn.  Extra remotes: {others}",
                file=sys.stderr,
            )
    ct = _connection_type(summary["has_cert"], summary["needs_password"])  # type: ignore[arg-type]
    if ct:
        options["connection-type"] = ct
    return options


def _maybe_inject_redirect_gateway(profile_bytes: bytes, already: bool) -> bytes:
    if already:
        return profile_bytes
    text = profile_bytes.decode("utf-8", errors="replace")
    injection = "redirect-gateway def1\n"
    m = re.search(r"^<[A-Za-z][A-Za-z0-9_-]*>\s*$", text, flags=re.MULTILINE)
    if m:
        text = text[: m.start()] + injection + text[m.start() :]
    else:
        text = text.rstrip() + "\n" + injection
    return text.encode("utf-8")


def _build_nmcli_cmd(con_name: str, vpn_data: str) -> list[str]:
    return [
        "nmcli", "connection", "add",
        "type", "vpn",
        "vpn-type", "org.freedesktop.NetworkManager.openvpn3",
        "con-name", con_name,
        "ifname", "*",
        "--",
        "vpn.data", vpn_data,
    ]


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Convert an .ovpn profile to an nmcli command for nm-openvpn3. "
            "Stages the .ovpn verbatim and points vpn.data at it.  Dry-run "
            "by default — pass --apply to actually write files and run nmcli."
        )
    )
    p.add_argument("ovpn", type=Path, help="path to the .ovpn file")
    p.add_argument("--con-name", default=None,
                   help="NM connection name (default: ovpn3-<stem>)")
    p.add_argument("--apply", action="store_true",
                   help="write profile.ovpn and run nmcli (default: dry-run)")
    p.add_argument("--full-tunnel", action="store_true",
                   help="inject 'redirect-gateway def1' into the staged profile "
                        "so openvpn3 installs 0.0.0.0/0 and NM promotes the VPN "
                        "to the system default route")
    args = p.parse_args()

    if not args.ovpn.is_file():
        print(f"error: {args.ovpn} not found or not a regular file", file=sys.stderr)
        return 2

    con_name = _validate_con_name(args.con_name or f"ovpn3-{args.ovpn.stem}")

    summary = _summary(args.ovpn)
    if not summary["remotes"]:
        print("error: .ovpn file has no 'remote' line", file=sys.stderr)
        return 3

    out_dir = Path.home() / ".config" / "nm-openvpn3" / con_name
    profile_path = out_dir / "profile.ovpn"
    profile_bytes = args.ovpn.read_bytes()
    if args.full_tunnel:
        new_bytes = _maybe_inject_redirect_gateway(
            profile_bytes, bool(summary["has_redirect_gateway"])
        )
        if new_bytes is not profile_bytes:
            profile_bytes = new_bytes
            print("[info] --full-tunnel: injected 'redirect-gateway def1' into staged profile",
                  file=sys.stderr)
        else:
            print("[info] --full-tunnel: profile already has redirect-gateway", file=sys.stderr)

    options = _cosmetic_vpn_data(profile_path, summary)
    vpn_data = ", ".join(f"{k}={v}" for k, v in options.items())
    cmd = _build_nmcli_cmd(con_name, vpn_data)

    if not args.apply:
        print("# dry-run mode (use --apply to actually run)")
        print(f"# connection name: {con_name}")
        print(f"# would create directory: {out_dir} (mode 0700)")
        print(f"#   would write: {profile_path} ({len(profile_bytes)} bytes, mode 0600)")
        print("# would run:")
        print(" \\\n  ".join(shlex.quote(part) for part in cmd))
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    profile_path.write_bytes(profile_bytes)
    os.chmod(profile_path, 0o600)
    print(f"[info] wrote verbatim .ovpn to {profile_path}", file=sys.stderr)
    print(" \\\n  ".join(shlex.quote(part) for part in cmd))
    print("\n[info] running: nmcli connection add ...", file=sys.stderr)
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
