#!/usr/bin/env python3
"""
share-dir-nfsfacl.py

Manage sharing ACLs on NFS via getfacl/setfacl over SSH.

Key idea:
- Determine which NFS server backs a given local PATH (mounted under /home, etc.)
- SSH to that NFS server and run getfacl/setfacl on the *server-side path*
- Log operations to ~/.shared_dirs (JSON Lines)
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List

LOG_PATH = Path.home() / ".shared_dirs"


@dataclass
class NfsMount:
    mountpoint: str        # local mountpoint, e.g. "/home"
    server: str            # server hostname/IP, e.g. "nfs1.example.org"
    export: str            # remote export path, e.g. "/srv/home"


def run_local(cmd: List[str], verbose: bool = False) -> subprocess.CompletedProcess:
    if verbose:
        print(f"[local] {shlex.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, text=True, capture_output=True)


def run_ssh(host: str, remote_cmd: str, verbose: bool = False) -> subprocess.CompletedProcess:
    """
    Run a command over SSH. remote_cmd is executed by the remote shell.
    """
    cmd = ["ssh", "-o", "BatchMode=yes", host, remote_cmd]
    if verbose:
        print(f"[ssh:{host}] {shlex.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, text=True, capture_output=True)


def parse_proc_mounts() -> List[NfsMount]:
    """
    Parse /proc/mounts and return NFS/NFS4 mounts.
    Example line:
      server:/export/path /home nfs4 rw,relatime,...
    """
    mounts: List[NfsMount] = []
    with open("/proc/mounts", "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            src, mnt, fstype = parts[0], parts[1], parts[2]
            if fstype not in ("nfs", "nfs4"):
                continue
            if ":" not in src:
                continue
            server, export = src.split(":", 1)
            mounts.append(NfsMount(mountpoint=mnt, server=server, export=export))

    # Prefer the longest mountpoint match
    mounts.sort(key=lambda m: len(m.mountpoint), reverse=True)
    return mounts


def find_nfs_mount_for_path(path: str, mounts: List[NfsMount]) -> Optional[NfsMount]:
    p = os.path.realpath(path)
    for m in mounts:
        if p == m.mountpoint or p.startswith(m.mountpoint.rstrip("/") + "/"):
            return m
    return None


def local_to_remote_path(local_path: str, mount: NfsMount) -> str:
    """
    Convert local absolute path into remote filesystem path.

    Example:
      mountpoint=/home, export=/srv/home
      local=/home/alice/share -> remote=/srv/home/alice/share
    """
    p = os.path.realpath(local_path)
    rel = os.path.relpath(p, mount.mountpoint)
    if rel == ".":
        return mount.export
    return os.path.normpath(os.path.join(mount.export, rel))


def resolve_subject(name: str, verbose: bool = False) -> Tuple[str, str]:
    """
    Decide whether name is a user or a group.

    Rules:
    - If name starts with '@' -> group
    - Else: try passwd, then group
    - Fallback: user
    """
    if name.startswith("@"):  # force group
        return "group", name[1:]

    r = run_local(["getent", "passwd", name], verbose=verbose)
    if r.returncode == 0 and r.stdout.strip():
        return "user", name

    r = run_local(["getent", "group", name], verbose=verbose)
    if r.returncode == 0 and r.stdout.strip():
        return "group", name

    return "user", name


def acl_perm_for_action(action: str) -> str:
    if action == "read":
        return "r-x"
    if action == "readwrite":
        return "rwx"
    raise ValueError(f"Unsupported action: {action}")


def log_action(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def cmd_show(server: str, remote_path: str, verbose: bool) -> int:
    r = run_ssh(server, f"getfacl -p {shlex.quote(remote_path)}", verbose=verbose)
    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def cmd_list() -> int:
    if not LOG_PATH.exists():
        print("(no log file)", file=sys.stderr)
        return 0

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            print(
                f"{rec.get('ts','?')}  {rec.get('action','?'):9}  "
                f"{rec.get('local_path','?')}  "
                f"{rec.get('subject_type','?')}:{rec.get('subject','?')}  "
                f"{rec.get('perms','')}  recurse={rec.get('recurse',False)}"
            )
    return 0


def apply_traverse_x(
    server: str,
    remote_target: str,
    export_root: str,
    subject_type: str,
    subject: str,
    verbose: bool,
    dry_run: bool,
) -> None:
    """
    Ensure subject can traverse parent directories up to the target.
    Uses '--x' only (minimal traversal).
    """
    stype = "u" if subject_type == "user" else "g"

    target = Path(remote_target)
    export = Path(export_root)

    parents = [p for p in target.parents if str(p).startswith(str(export))]
    parents = sorted(parents, key=lambda p: len(str(p)))

    cmds = []
    for d in parents:
        cmds.append(f"setfacl -m {stype}:{shlex.quote(subject)}:--x {shlex.quote(str(d))}")

    if not cmds:
        return

    remote_cmd = " && ".join(cmds)
    if dry_run:
        print(f"[dry-run] ssh {server} {remote_cmd}", file=sys.stderr)
        return

    r = run_ssh(server, remote_cmd, verbose=verbose)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())


def build_setfacl_cmds(
    action: str,
    remote_path: str,
    subject_type: str,
    subject: str,
    recurse: bool,
) -> List[str]:
    perms = acl_perm_for_action(action)
    stype = "u" if subject_type == "user" else "g"

    cmds = []

    # Access ACL on root
    cmds.append(f"setfacl -m {stype}:{shlex.quote(subject)}:{perms} {shlex.quote(remote_path)}")

    # Default ACL on directory
    cmds.append(
        f"if [ -d {shlex.quote(remote_path)} ]; then "
        f"setfacl -m d:{stype}:{shlex.quote(subject)}:{perms} {shlex.quote(remote_path)}; fi"
    )

    if recurse:
        cmds.append(
            f"if [ -d {shlex.quote(remote_path)} ]; then "
            f"setfacl -R -m {stype}:{shlex.quote(subject)}:{perms} {shlex.quote(remote_path)}; fi"
        )
        cmds.append(
            f"if [ -d {shlex.quote(remote_path)} ]; then "
            f"find {shlex.quote(remote_path)} -type d -print0 | "
            f"xargs -0 -r setfacl -m d:{stype}:{shlex.quote(subject)}:{perms}; fi"
        )

    return cmds


def build_remove_acl_cmds(
    remote_path: str,
    subject_type: str,
    subject: str,
    recurse: bool,
) -> List[str]:
    stype = "u" if subject_type == "user" else "g"

    cmds = []

    cmds.append(f"setfacl -x {stype}:{shlex.quote(subject)} {shlex.quote(remote_path)} || true")
    cmds.append(
        f"if [ -d {shlex.quote(remote_path)} ]; then "
        f"setfacl -x d:{stype}:{shlex.quote(subject)} {shlex.quote(remote_path)} || true; fi"
    )

    if recurse:
        cmds.append(
            f"if [ -d {shlex.quote(remote_path)} ]; then "
            f"setfacl -R -x {stype}:{shlex.quote(subject)} {shlex.quote(remote_path)} || true; fi"
        )
        cmds.append(
            f"if [ -d {shlex.quote(remote_path)} ]; then "
            f"find {shlex.quote(remote_path)} -type d -print0 | "
            f"xargs -0 -r setfacl -x d:{stype}:{shlex.quote(subject)} || true; fi"
        )

    return cmds


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Manage sharing ACLs on NFS via getfacl/setfacl over SSH"
    )
    ap.add_argument("action", choices=["read", "readwrite", "undo", "show", "list"])
    ap.add_argument("path", nargs="?", help="Local path under NFS mount")
    ap.add_argument("subject", nargs="?", help="LOGIN or GROUP (use @group to force group)")
    ap.add_argument("-r", "--recurse", action="store_true")
    ap.add_argument("-n", "--dry-run", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.action == "list":
        return cmd_list()

    if not args.path:
        ap.error("PATH is required")

    mounts = parse_proc_mounts()
    mount = find_nfs_mount_for_path(args.path, mounts)
    if not mount:
        print("ERROR: PATH is not on an NFS mount", file=sys.stderr)
        return 2

    remote_path = local_to_remote_path(args.path, mount)

    if args.action == "show":
        return cmd_show(mount.server, remote_path, args.verbose)

    if args.action in ("read", "readwrite", "undo") and not args.subject:
        ap.error("LOGIN|GROUP is required")

    subject_type, subject = resolve_subject(args.subject, args.verbose)

    if args.action in ("read", "readwrite"):
        apply_traverse_x(
            mount.server,
            remote_path,
            mount.export,
            subject_type,
            subject,
            args.verbose,
            args.dry_run,
        )

        cmds = build_setfacl_cmds(
            args.action,
            remote_path,
            subject_type,
            subject,
            args.recurse,
        )
        remote_cmd = " && ".join(cmds)

        if args.dry_run:
            print(f"[dry-run] ssh {mount.server} {remote_cmd}", file=sys.stderr)
        else:
            r = run_ssh(mount.server, remote_cmd, args.verbose)
            sys.stdout.write(r.stdout)
            sys.stderr.write(r.stderr)
            if r.returncode != 0:
                return r.returncode

        log_action({
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "action": args.action,
            "local_path": os.path.realpath(args.path),
            "nfs_server": mount.server,
            "export": mount.export,
            "remote_path": remote_path,
            "subject_type": subject_type,
            "subject": subject,
            "perms": acl_perm_for_action(args.action),
            "recurse": bool(args.recurse),
            "dry_run": bool(args.dry_run),
        })
        return 0

    if args.action == "undo":
        cmds = build_remove_acl_cmds(
            remote_path,
            subject_type,
            subject,
            args.recurse,
        )
        remote_cmd = " && ".join(cmds)

        if args.dry_run:
            print(f"[dry-run] ssh {mount.server} {remote_cmd}", file=sys.stderr)
        else:
            r = run_ssh(mount.server, remote_cmd, args.verbose)
            sys.stdout.write(r.stdout)
            sys.stderr.write(r.stderr)
            if r.returncode != 0:
                return r.returncode

        log_action({
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "action": "undo",
            "local_path": os.path.realpath(args.path),
            "nfs_server": mount.server,
            "export": mount.export,
            "remote_path": remote_path,
            "subject_type": subject_type,
            "subject": subject,
            "recurse": bool(args.recurse),
            "dry_run": bool(args.dry_run),
        })
        return 0

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
