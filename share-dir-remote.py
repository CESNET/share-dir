#!/usr/bin/env python3
"""share-dir-remote: run share-dir on the NFS server for a given PATH.

Problem:
  On some clients (e.g., /home mounted via NFS), setting POSIX ACLs directly on
  the mounted path may be unsupported or undesired. This wrapper detects the NFS
  server backing PATH and runs share-dir on the server via SSH.

What it does:
  1) Detect the mount source for PATH (server:/export) using findmnt.
  2) Translate client PATH to server filesystem PATH:
        server_path = export_path + relpath(PATH, mount_target)
  3) SSH to the server and invoke share-dir with the same arguments, but with
     PATH replaced by server_path.

Usage:
  Use it exactly like share-dir (same arguments), e.g.:

    share-dir-remote read /home/alice/share g:einfra
    share-dir-remote -r readwrite /home/alice/share u:dexter
    share-dir-remote undo -p /home/alice/share
    share-dir-remote show /home/alice/share
    share-dir-remote list

Assumptions:
  - The NFS export path on the server is a real local path (as shown in SOURCE).
  - The relative layout under the mount target matches the export on the server.

Configuration (optional via env vars):
  - SHARE_DIR_REMOTE_USER: SSH username (default: current user)
  - SHARE_DIR_REMOTE_BIN:  remote share-dir command (default: "share-dir")
  - SHARE_DIR_SSH:         ssh binary (default: "ssh")
  - SHARE_DIR_SSH_OPTS:    extra ssh opts (e.g. "-J jump-host")
  - SHARE_DIR_REMOTE_LOG=1
      Enable INFO-level logging (mount detection, path translation, SSH command).
  - SHARE_DIR_REMOTE_DEBUG=1
      Enable DEBUG-level logging (includes argv and internal details).
  - SHARE_DIR_REMOTE_DRY_RUN=1
      Dry-run mode: print the SSH command and exit successfully without
      executing it (no SSH connection is made).
"""

from __future__ import annotations

import os
import pwd
import shlex
import subprocess
import sys
import logging
from pathlib import Path
from typing import List, Tuple


COMMANDS = {"read", "readwrite", "undo", "show", "list"}

LOG = logging.getLogger("share-dir-remote")


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse common boolean-ish environment values."""
    v = os.environ.get(name)
    if v is None:
        return default
    v = v.strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _cmd_str(cmd: List[str]) -> str:
    """Render a command safely for display."""
    try:
        return shlex.join(cmd)
    except AttributeError:
        # Python < 3.8 fallback
        return " ".join(shlex.quote(c) for c in cmd)



def _current_user() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "") or "root"


def _run(cmd: List[str]) -> str:
    p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout.strip()


def find_nfs_mount_info(path: Path) -> Tuple[str, Path, str, Path]:
    """Return (server, mount_target, export_path, server_path_for_input)."""
    # SOURCE TARGET FSTYPE
    out = _run(["findmnt", "-n", "-o", "SOURCE,TARGET,FSTYPE", "-T", str(path)])
    if not out:
        raise SystemExit(f"Could not determine mount for: {path}")

    parts = out.split()
    if len(parts) < 3:
        raise SystemExit(f"Unexpected findmnt output for {path!s}: {out!r}")

    source, target, fstype = parts[0], parts[1], parts[2]

    if not (fstype.startswith("nfs")):
        raise SystemExit(
            f"Path {path} is on filesystem type '{fstype}', not NFS. "
            "Refusing to run remote wrapper."
        )

    if ":" not in source:
        raise SystemExit(f"Unexpected NFS SOURCE format (expected server:/export): {source}")

    server, export = source.split(":", 1)
    mount_target = Path(target).resolve()

    # Translate client path -> server local path: export + relative path under mount target
    input_path = path.resolve()
    try:
        rel = input_path.relative_to(mount_target)
    except ValueError:
        # Should not happen if findmnt -T is correct, but keep a safe fallback.
        rel = Path(os.path.relpath(str(input_path), str(mount_target)))

    export_path = Path(export)
    if str(rel) == ".":
        server_path = export_path
    else:
        server_path = export_path / rel

    return server, mount_target, export_path, server_path


def locate_command_and_path(argv: List[str]) -> Tuple[int, str, int | None]:
    """Return (cmd_index, cmd, path_index or None)."""
    cmd_idx = None
    cmd = None

    for i, tok in enumerate(argv):
        if tok in COMMANDS:
            cmd_idx = i
            cmd = tok
            break

    if cmd_idx is None or cmd is None:
        raise SystemExit(
            "Could not find action (read/readwrite/undo/show/list) in arguments. "
            "Pass arguments like you would to share-dir."
        )

    if cmd == "list":
        return cmd_idx, cmd, None

    # share-dir expects PATH immediately after the action
    if cmd_idx + 1 >= len(argv):
        raise SystemExit(f"Missing PATH after action '{cmd}'")

    return cmd_idx, cmd, cmd_idx + 1


def main() -> None:
    argv = sys.argv[1:]

    # Environment-controlled logging and dry-run (no SSH execution)
    log_enabled = _env_bool("SHARE_DIR_REMOTE_LOG", default=False)
    log_debug = _env_bool("SHARE_DIR_REMOTE_DEBUG", default=False)
    dry_run_env = _env_bool("SHARE_DIR_REMOTE_DRY_RUN", default=False)

    if log_enabled or log_debug:
        logging.basicConfig(
            level=logging.DEBUG if log_debug else logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )


    cmd_idx, cmd, path_idx = locate_command_and_path(argv)

    ssh_bin = os.environ.get("SHARE_DIR_SSH", "ssh")
    ssh_opts = shlex.split(os.environ.get("SHARE_DIR_SSH_OPTS", ""))
    remote_bin = os.environ.get("SHARE_DIR_REMOTE_BIN", "share-dir")

    LOG.debug("argv=%s", argv)

    if path_idx is None:
        # list: no PATH translation needed
        remote_args = argv
        server = os.environ.get("SHARE_DIR_REMOTE_DEFAULT_SERVER")
        if not server:
            raise SystemExit(
                "Action 'list' has no PATH, so the NFS server cannot be inferred. "
                "Set SHARE_DIR_REMOTE_DEFAULT_SERVER=host to use list remotely."
            )
    else:
        local_path = Path(argv[path_idx]).expanduser()
        server, mount_target, export_path, server_path = find_nfs_mount_info(local_path)
        LOG.info("NFS mount: %s is on %s:%s mounted at %s", local_path, server, export_path, mount_target)
        LOG.info("Translated server path: %s", server_path)

        # Replace local PATH with server-side filesystem path
        remote_args = list(argv)
        remote_args[path_idx] = str(server_path)

    remote_user = os.environ.get("SHARE_DIR_REMOTE_USER", _current_user())
    ssh_target = f"{remote_user}@{server}" if remote_user else server

    # Build SSH command. Use '--' to terminate ssh options.
    ssh_cmd = [ssh_bin, *ssh_opts, ssh_target, "--", remote_bin, *remote_args]

    LOG.info("SSH command: %s", _cmd_str(ssh_cmd))

    if dry_run_env:
        # Dry run requested via environment: do NOT execute SSH.
        LOG.warning("DRY RUN enabled via SHARE_DIR_REMOTE_DRY_RUN=1 — SSH command will NOT be executed.")
        print(_cmd_str(ssh_cmd))
        raise SystemExit(0)

    # Execute and propagate exit code
    try:
        proc = subprocess.run(ssh_cmd)
    except FileNotFoundError as e:
        raise SystemExit(f"Missing required binary: {e}")

    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
