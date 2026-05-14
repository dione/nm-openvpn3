#!/usr/bin/env python3
"""
Read an OpenVPN .ovpn profile and emit an `nmcli connection add` command
that creates an nm-openvpn3 VPN connection.

Usage:
    scripts/ovpn-to-nmcli.py PROFILE.ovpn [--con-name NAME] [--apply]

Behaviour:
- Parses the .ovpn file (including inline <ca>/<cert>/<key>/<tls-auth> blocks).
- For inline blocks, writes their content to ~/.config/nm-openvpn3/<name>/
  with 0600 perms and uses the on-disk path in vpn.data.
- Maps OpenVPN options to the same vpn.data keys NetworkManager-openvpn uses
  (see properties/import-export.c in upstream NM-openvpn for the canonical
  list — the same keys are accepted by nm-openvpn3 because Plan 1 reuses
  do_export from the upstream properties library).
- Prints the resulting `nmcli` command. With --apply, runs it directly.

Notes:
- vpn.data is a single semicolon-separated string of key=value pairs.
- Username/password secrets are NOT written here.  Use --ask or set
  vpn.secrets after the connection exists if you need them.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

# Block tags that may contain inline PEM/key data.
INLINE_TAGS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")

# OpenVPN options that NM does not model individually but that are harmless
# defaults (or runtime tweaks the openvpn3 client handles itself).  Silenced
# so the dry-run output stays signal-heavy.
SILENT_OPTS = {
    "nobind", "verb", "server-poll-timeout", "push-peer-info",
    "resolv-retry", "persist-key", "persist-tun", "explicit-exit-notify",
    "pull", "redirect-gateway", "topology", "route-method", "route-delay",
    "nice", "syslog", "daemon", "tls-client", "key-direction",
    "auth-user-pass",   # handled separately for connection-type heuristic
}

# Mapping from .ovpn option name to the NM vpn.data key.  Only options that
# the upstream NM-openvpn editor recognises are emitted; everything else is
# logged to stderr and dropped.
DIRECT_KEYS: dict[str, str] = {
    "ca": "ca",
    "cert": "cert",
    "key": "key",
    "tls-auth": "ta",
    "tls-crypt": "tls-crypt",
    "cipher": "cipher",
    "auth": "auth",
    "comp-lzo": "comp-lzo",
    "tls-remote": "tls-remote",
    "remote-cert-tls": "remote-cert-tls",
    "ns-cert-type": "ns-cert-type",
    "verify-x509-name": "verify-x509-name",
    "dev": "dev",
    "dev-type": "dev-type",
    "tun-mtu": "tun-mtu",
    "fragment": "fragment-size",
    "mssfix": "mssfix",
    "port": "port",
    "ping": "ping",
    "ping-restart": "ping-restart",
    "ping-exit": "ping-exit",
    "reneg-sec": "reneg-seconds",
    "tun-ipv6": "tun-ipv6",
    "float": "float",
    "auth-nocache": "auth-nocache",
    "tls-version-min": "tls-version-min",
}


def parse_ovpn(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Return (options, inline_blocks).

    options: flattened key/value map (multi-value keys collapsed to last).
    inline_blocks: tag -> contents (raw PEM/key text without the wrapping tags).
    """
    options: dict[str, str] = {}
    inline_blocks: dict[str, str] = {}
    remotes: list[tuple[str, str | None, str | None]] = []  # (host, port?, proto?)

    current_block: str | None = None
    block_lines: list[str] = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        # Block close
        if current_block is not None:
            close_tag = f"</{current_block}>"
            if stripped == close_tag:
                inline_blocks[current_block] = "\n".join(block_lines).strip() + "\n"
                current_block = None
                block_lines = []
            else:
                block_lines.append(line)
            continue

        # Block open
        for tag in INLINE_TAGS:
            if stripped == f"<{tag}>":
                current_block = tag
                block_lines = []
                break
        if current_block is not None:
            continue

        # Plain option line
        tokens = shlex.split(stripped, comments=False, posix=True)
        if not tokens:
            continue
        key, *rest = tokens

        if key == "remote":
            host = rest[0] if rest else ""
            port = rest[1] if len(rest) > 1 else None
            proto = rest[2] if len(rest) > 2 else None
            remote_tuple = (host, port, proto)
            if remote_tuple not in remotes:
                remotes.append(remote_tuple)
            continue

        if key in DIRECT_KEYS:
            options[DIRECT_KEYS[key]] = " ".join(rest) if rest else "yes"
            continue

        if key == "client":
            options["client"] = "yes"
        elif key == "proto":
            options["proto"] = rest[0] if rest else ""
        elif key == "auth-user-pass":
            options["__needs_password__"] = "yes"
        elif key in SILENT_OPTS:
            pass   # handled-by-default openvpn options that NM does not model
        else:
            # not fatal — note and drop
            print(f"[warn] unmapped option: {stripped}", file=sys.stderr)

    # Compose remote.  NM vpn.data uses comma-separated entries for multi-remote.
    if remotes:
        parts = []
        for host, port, proto in remotes:
            piece = host
            if port:
                piece += f":{port}"
            if proto:
                piece += f":{proto}"
            parts.append(piece)
        options["remote"] = ", ".join(parts)

    # Connection-type heuristic.
    has_cert = "cert" in options or "cert" in inline_blocks
    needs_pw = options.pop("__needs_password__", None)
    if has_cert and needs_pw:
        options["connection-type"] = "password-tls"
    elif has_cert:
        options["connection-type"] = "tls"
    elif needs_pw:
        options["connection-type"] = "password"

    # Proto: if any remote line set proto=tcp, surface as proto-tcp=yes (legacy NM key).
    proto = options.pop("proto", "")
    if proto.startswith("tcp"):
        options["proto-tcp"] = "yes"

    return options, inline_blocks


NM_KEY_FOR_TAG = {
    "ca": "ca",
    "cert": "cert",
    "key": "key",
    "tls-auth": "ta",
    "tls-crypt": "tls-crypt",
    "tls-crypt-v2": "tls-crypt-v2",
}
TAG_EXTENSIONS = {
    "ca": ".crt",
    "cert": ".crt",
    "key": ".key",
    "tls-auth": ".key",
    "tls-crypt": ".key",
    "tls-crypt-v2": ".key",
}


def plan_inline_paths(
    inline: dict[str, str],
    con_name: str,
    options: dict[str, str],
) -> tuple[Path | None, list[tuple[Path, int]]]:
    """Decide where each inline block will be written and patch options
    accordingly.  Returns (out_dir, [(path, bytes_to_write), ...]).
    Does NOT touch the filesystem.
    """
    if not inline:
        return None, []
    out_dir = Path.home() / ".config" / "nm-openvpn3" / con_name
    plan: list[tuple[Path, int]] = []
    for tag, content in inline.items():
        fname = f"{tag}{TAG_EXTENSIONS.get(tag, '.pem')}"
        fpath = out_dir / fname
        plan.append((fpath, len(content.encode("utf-8"))))
        options[NM_KEY_FOR_TAG[tag]] = str(fpath)
    return out_dir, plan


def write_inline_blocks(
    inline: dict[str, str],
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    for tag, content in inline.items():
        fname = f"{tag}{TAG_EXTENSIONS.get(tag, '.pem')}"
        fpath = out_dir / fname
        fpath.write_text(content)
        os.chmod(fpath, 0o600)


def build_vpn_data(options: dict[str, str]) -> str:
    parts = [f"{k}={v}" for k, v in options.items()]
    return ", ".join(parts)


def build_nmcli_cmd(con_name: str, vpn_data: str) -> list[str]:
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
            "Dry-run by default: prints what it would do without writing "
            "files or running nmcli.  Pass --apply to actually do it."
        )
    )
    p.add_argument("ovpn", type=Path, help="path to the .ovpn file")
    p.add_argument("--con-name", default=None,
                   help="NM connection name (default: ovpn3-<stem>)")
    p.add_argument("--apply", action="store_true",
                   help="write inline cert/key files and run nmcli (default: dry-run)")
    args = p.parse_args()

    if not args.ovpn.is_file():
        print(f"error: {args.ovpn} not found or not a regular file", file=sys.stderr)
        return 2

    con_name = args.con_name or f"ovpn3-{args.ovpn.stem}"

    options, inline = parse_ovpn(args.ovpn)
    out_dir, plan = plan_inline_paths(inline, con_name, options)

    if "remote" not in options:
        print("error: .ovpn file has no 'remote' line", file=sys.stderr)
        return 3

    vpn_data = build_vpn_data(options)
    cmd = build_nmcli_cmd(con_name, vpn_data)

    if not args.apply:
        # Dry-run preview.
        print(f"# dry-run mode (use --apply to actually run)")
        print(f"# connection name: {con_name}")
        if out_dir:
            print(f"# would create directory: {out_dir} (mode 0700)")
            for fpath, nbytes in plan:
                print(f"#   would write: {fpath} ({nbytes} bytes, mode 0600)")
        print(f"# would run:")
        print(" \\\n  ".join(shlex.quote(part) for part in cmd))
        return 0

    # Apply mode.
    if out_dir:
        write_inline_blocks(inline, out_dir)
        print(f"[info] wrote inline cert/key material to {out_dir}", file=sys.stderr)
    print(" \\\n  ".join(shlex.quote(part) for part in cmd))
    print(f"\n[info] running: nmcli connection add ...", file=sys.stderr)
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
