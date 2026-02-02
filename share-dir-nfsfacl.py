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
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List

LOG_PATH = Path.home() / ".shared_dirs"

# Allowed roots for sharing (colon paths)
# Example: "$HOME:/storage:/scratch"
SHARE_DIR_ALLOWED_ROOTS = os.environ.get(
    "SHARE_DIR_ALLOWED_ROOTS",
    f"{Path.home().resolve()}:/storage:/scratch"
)

# Unified module logger
log = logging.getLogger("share-dir-nfsacl")

@dataclass
class NfsMount:
    mountpoint: str        # local mountpoint, e.g. "/home"
    server: str            # server hostname/IP, e.g. "nfs1.example.org"
    export: str            # remote export path, e.g. "/srv/home"


def run_local(cmd: List[str]) -> subprocess.CompletedProcess:
    log.debug("[local] %s", shlex.join(cmd))
    return subprocess.run(cmd, text=True, capture_output=True)


def run_ssh(host: str, remote_cmd: str) -> subprocess.CompletedProcess:
    cmd = ["ssh", "-o", "BatchMode=yes", host, remote_cmd]
    log.debug("[ssh:%s] %s", host, shlex.join(cmd))
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


def resolve_subject(name: str) -> Tuple[str, str]:
    """
    Decide whether name is a user or a group.

    Rules:
    - If name starts with '@' -> group
    - Else: try passwd, then group
    - Fallback: user
    """
    if name.startswith("@"):  # force group
        return "group", name[1:]

    r = run_local(["getent", "passwd", name])
    if r.returncode == 0 and r.stdout.strip():
        return "user", name

    r = run_local(["getent", "group", name])
    if r.returncode == 0 and r.stdout.strip():
        return "group", name

    return "user", name


def acl_perm_for_action(action: str) -> str:
    if action == "read":
        return "r-X"
    if action == "readwrite":
        return "rwX"
    raise ValueError(f"Unsupported action: {action}")


def log_action(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def handle_show(args, server: str, remote_path: str) -> int:
    show_command_base = ["getfacl", "-p" ]
    if args.recurse:
        show_command_base.append("-R")
    
    show_command =  " ".join(show_command_base) + f" {shlex.quote(remote_path)}"

    r = run_ssh(server, show_command)
    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)
    return r.returncode


def handle_list() -> int:
    if not LOG_PATH.exists():
        log.info("No log file")
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
            log.info(
                f"{rec.get('ts','?')}  {rec.get('action','?'):9}  "
                f"{rec.get('local_path','?')}  "
                f"{rec.get('subject_type','?')}:{rec.get('subject','?')}  "
                f"{rec.get('perms','')}  recurse={rec.get('recurse',False)}"
            )
    return 0


def apply_traverse_x(
    server: str,
    remote_target: str,
    stop_root: str,
    subject_type: str,
    subject: str,
    dry_run: bool,
) -> None:
    """Ensure subject can traverse parent directories from `stop_root` down to `remote_target`.

    We intentionally stop at the configured allowed root (mapped to a remote path), not at the NFS export
    mountpoint. This prevents the tool from touching broader directory levels than intended.

    We use '--x' only (minimal traversal).
    """
    stype = "u" if subject_type == "user" else "g"

    target = Path(remote_target)
    boundary = Path(stop_root)

    # Collect directories we will touch: boundary + parents under boundary.
    dirs: List[Path] = []

    # Add boundary itself if it is an ancestor (or equals target).
    try:
        target.relative_to(boundary)
        dirs.append(boundary)
    except ValueError:
        # If the boundary is not an ancestor, do nothing (shouldn't happen if local checks are correct).
        log.warning("stop_root '%s' is not an ancestor of '%s'", boundary, target)
        return

    for p in target.parents:
        try:
            p.relative_to(boundary)
        except ValueError:
            continue
        dirs.append(p)

    # Sort from shallow to deep so traversal is granted in a sensible order.
    dirs = sorted(set(dirs), key=lambda p: len(str(p)))

    paths = [shlex.quote(str(d)) for d in dirs if str(d) != "/"]

    if not paths:
        return

    # Apply the same ACL modification to all parent directories in a single call
    remote_cmd = (
        f"setfacl -m {stype}:{shlex.quote(subject)}:--x "
        + " ".join(paths)
    )
    if dry_run:
        log.info(f"[dry-run] ssh {server} {remote_cmd}")
        return

    r = run_ssh(server, remote_cmd)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())


def remove_parent_acl_entry(
    server: str,
    remote_target: str,
    stop_root: str,
    subject_type: str,
    subject: str,
    dry_run: bool,
) -> None:
    """Remove the subject ACL entry from parent directories up to `stop_root`.

    WARNING: This may break other sharing setups, because it removes the *entire* ACL entry
    (e.g., u:alice or g:team) on those parent directories, not only the '--x' bit.
    """
    stype = "u" if subject_type == "user" else "g"

    target = Path(remote_target)
    boundary = Path(stop_root)

    dirs: List[Path] = []

    try:
        target.relative_to(boundary)
        dirs.append(boundary)
    except ValueError:
        log.warning("stop_root '%s' is not an ancestor of '%s'", boundary, target)
        return

    for p in target.parents:
        try:
            p.relative_to(boundary)
        except ValueError:
            continue
        dirs.append(p)

    dirs = sorted(set(dirs), key=lambda p: len(str(p)))
    paths = [shlex.quote(str(d)) for d in dirs if str(d) != "/"]

    if not paths:
        return

    remote_cmd = f"setfacl -x {stype}:{shlex.quote(subject)} " + " ".join(paths)

    if dry_run:
        log.info(f"[dry-run] ssh {server} {remote_cmd}")
        return

    r = run_ssh(server, remote_cmd)
    if r.returncode != 0:
        # Best-effort: missing entries are okay.
        log.warning("parent ACL cleanup failed (ignored): %s", r.stderr.strip())


def _allowed_roots_paths() -> List[Path]:
    """Parse SHARE_DIR_ALLOWED_ROOTS into resolved Path objects."""
    roots: List[Path] = []
    for raw in SHARE_DIR_ALLOWED_ROOTS.split(":"):
        raw = raw.strip()
        if not raw:
            continue
        roots.append(Path(raw).expanduser().resolve())
    # Prefer the longest match
    roots.sort(key=lambda p: len(str(p)), reverse=True)
    return roots


def find_allowed_root_for_path(path: Path) -> Optional[Path]:
    """Return the deepest allowed root that contains `path` (both resolved)."""
    p = path.expanduser().resolve()
    for root in _allowed_roots_paths():
        try:
            p.relative_to(root)
            return root
        except ValueError:
            continue
    return None


def _chunk_by_argv_limit(items: List[str], base_len: int, max_len: int = 7000) -> List[List[str]]:
    """Chunk a list of already-escaped items so each command stays under a rough length limit."""
    chunks: List[List[str]] = []
    cur: List[str] = []
    cur_len = base_len

    for it in items:
        add_len = len(it) + 1
        if cur and (cur_len + add_len) > max_len:
            chunks.append(cur)
            cur = [it]
            cur_len = base_len + len(it)
        else:
            cur.append(it)
            cur_len += add_len

    if cur:
        chunks.append(cur)

    return chunks


def collect_local_targets(path: Path, recurse: bool) -> Tuple[List[Path], List[Path]]:
    """Return (all_targets, dir_targets) for ACL changes.

    Rules:
    - If PATH is a file: all_targets=[PATH], dir_targets=[]
    - If PATH is a directory:
      - apply ACL to PATH and its contents
      - without -r: only immediate children
      - with -r: walk recursively
    - dir_targets contains directories that should receive *default* ACL.

    This is evaluated locally on the FE so the remote side can be a pure setfacl invocation
    (no shell operators like 'if', '&&', pipes), which is compatible with jailkit.
    """
    p = path.expanduser().resolve()

    if p.is_dir():
        all_targets: List[Path] = [p]
        dir_targets: List[Path] = [p]

        if recurse:
            for root, dirs, files in os.walk(p):
                root_p = Path(root)
                for d in dirs:
                    dp = root_p / d
                    all_targets.append(dp)
                    dir_targets.append(dp)
                for f in files:
                    all_targets.append(root_p / f)
        else:
            try:
                for child in p.iterdir():
                    all_targets.append(child)
                    if child.is_dir():
                        dir_targets.append(child)
            except PermissionError:
                pass

        # De-dup while preserving order
        seen = set()
        all_u: List[Path] = []
        for t in all_targets:
            s = str(t)
            if s in seen:
                continue
            seen.add(s)
            all_u.append(t)

        seen = set()
        dir_u: List[Path] = []
        for t in dir_targets:
            s = str(t)
            if s in seen:
                continue
            seen.add(s)
            dir_u.append(t)

        return all_u, dir_u

    # File / special path
    return [p], []


def build_setfacl_commands(
    action: str,
    subject_type: str,
    subject: str,
    remote_targets: List[str],
    remote_dir_targets: List[str],
    owner_user: Optional[str] = None,
    recurse: bool = False,
) -> List[str]:
    """Build remote *single-command* invocations (no shell operators)."""
    perms = acl_perm_for_action(action)
    stype = "u" if subject_type == "user" else "g"

    cmds: List[str] = []
    recursive_flag = " -R" if recurse else ""

    base = f"setfacl{recursive_flag} -m {stype}:{shlex.quote(subject)}:{perms}"
    for ch in _chunk_by_argv_limit(remote_targets, base_len=len(base)):
        cmds.append(base + " " + " ".join(ch))

    if remote_dir_targets:
        extra_default = ""
        if owner_user and not (subject_type == "user" and subject == owner_user):
            extra_default = f",d:u:{shlex.quote(owner_user)}:rwX"

        base_d = f"setfacl{recursive_flag} -m d:{stype}:{shlex.quote(subject)}:{perms}{extra_default}"
        for ch in _chunk_by_argv_limit(remote_dir_targets, base_len=len(base_d)):
            cmds.append(base_d + " " + " ".join(ch))

    return cmds


def build_remove_acl_commands(
    subject_type: str,
    subject: str,
    remote_targets: List[str],
    remote_dir_targets: List[str],
    recurse: bool = False,
) -> List[str]:
    """Build remote *single-command* invocations for undo (no shell operators)."""
    stype = "u" if subject_type == "user" else "g"

    cmds: List[str] = []
    recursive_flag = " -R" if recurse else ""

    base = f"setfacl{recursive_flag} -x {stype}:{shlex.quote(subject)}"
    for ch in _chunk_by_argv_limit(remote_targets, base_len=len(base)):
        cmds.append(base + " " + " ".join(ch))

    if remote_dir_targets:
        base_d = f"setfacl{recursive_flag} -x d:{stype}:{shlex.quote(subject)}"
        for ch in _chunk_by_argv_limit(remote_dir_targets, base_len=len(base_d)):
            cmds.append(base_d + " " + " ".join(ch))

    return cmds


def is_path_allowed(path: Path) -> bool:
    """
    Check whether the given path is under one of the allowed roots.

    Special case:
    - If allowed root is $HOME, user may only operate *below* $HOME (not on $HOME itself).
    """
    p = path.resolve()
    log.debug(f"checking is_path_allowed: {p} in {SHARE_DIR_ALLOWED_ROOTS}")
    for root in SHARE_DIR_ALLOWED_ROOTS.split(":"):
        try:
            p.relative_to(Path(root))
        except ValueError:
            continue

        # Disallow operating directly on the root itself (e.g. /home or /home/user)
        root_p = Path(root).expanduser().resolve()
        if p == root_p:
            return False

        return True
    return False


def current_user_name() -> str:
    """Return the logical 'current user' for default-owner ACL entry.

    Preference order:
    - SUDO_USER (if invoked via sudo wrapper)
    - USER env
    - getpass.getuser()
    """
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or getpass.getuser()


def handle_read_readwrite(args, mount: NfsMount) -> int:
    # Determine which allowed root matched the local PATH, map it to the remote filesystem,
    # and use it as the boundary for parent-directory traverse ACLs.
    local_allowed_root = find_allowed_root_for_path(Path(args.path))
    if not local_allowed_root:
        log.error("Internal error: could not determine matching allowed root for '%s'", args.path)
        return 3
    remote_allowed_root = local_to_remote_path(str(local_allowed_root), mount)

    remote_path = local_to_remote_path(args.path, mount)

    apply_traverse_x(
        mount.server,
        remote_path,
        remote_allowed_root,
        resolve_subject(args.subject)[0],
        resolve_subject(args.subject)[1],
        args.dry_run,
    )

    # Pre-check PATH locally so remote side can be a pure setfacl invocation (no shell syntax).
    local_targets, local_dir_targets = collect_local_targets(Path(args.path), False)

    # Map local targets to remote filesystem paths
    remote_targets = [shlex.quote(local_to_remote_path(str(p), mount)) for p in local_targets]
    remote_dir_targets = [shlex.quote(local_to_remote_path(str(p), mount)) for p in local_dir_targets]

    subject_type, subject = resolve_subject(args.subject)

    cmds = build_setfacl_commands(
        args.action,
        subject_type,
        subject,
        remote_targets,
        remote_dir_targets,
        owner_user=current_user_name(),
        recurse=bool(args.recurse),
    )

    for remote_cmd in cmds:
        if args.dry_run:
            log.info(f"[dry-run] ssh {mount.server} {remote_cmd}")
            continue

        r = run_ssh(mount.server, remote_cmd)
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


def handle_undo(args, mount: NfsMount) -> int:
    if args.parent:
        log.warning(
            "You used --parent: this will remove ACL entries on parent directories too. "
            "This may break other sharing configurations that rely on the same user/group entry."
        )

    subject_type, subject = resolve_subject(args.subject)
    remote_path = local_to_remote_path(args.path, mount)

    local_targets, local_dir_targets = collect_local_targets(Path(args.path), False)
    remote_targets = [shlex.quote(local_to_remote_path(str(p), mount)) for p in local_targets]
    remote_dir_targets = [shlex.quote(local_to_remote_path(str(p), mount)) for p in local_dir_targets]

    cmds = build_remove_acl_commands(
        subject_type,
        subject,
        remote_targets,
        remote_dir_targets,
        recurse=bool(args.recurse),
    )

    for remote_cmd in cmds:
        if args.dry_run:
            log.info(f"[dry-run] ssh {mount.server} {remote_cmd}")
            continue

        r = run_ssh(mount.server, remote_cmd)
        sys.stdout.write(r.stdout)
        sys.stderr.write(r.stderr)
        if r.returncode != 0:
            log.warning("undo command failed (ignored): %s", r.stderr.strip())

    if args.parent:
        local_allowed_root = find_allowed_root_for_path(Path(args.path))
        if not local_allowed_root:
            log.error("Internal error: could not determine matching allowed root for '%s'", args.path)
            return 3
        remote_allowed_root = local_to_remote_path(str(local_allowed_root), mount)
        remove_parent_acl_entry(
            mount.server,
            remote_path,
            remote_allowed_root,
            subject_type,
            subject,
            args.dry_run,
        )

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


def build_arg_parser() -> argparse.ArgumentParser:
    common_opts = argparse.ArgumentParser(add_help=False)
    common_opts.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    common_opts.add_argument("-n", "--dry-run", action="store_true")
    common_opts.add_argument("-r", "--recurse", action="store_true")

    parser = argparse.ArgumentParser(
        description="Manage sharing ACLs on NFS via getfacl/setfacl over SSH",
        parents=[common_opts],
    )

    subparsers = parser.add_subparsers(dest="action", required=True, metavar="ACTION")

    read_parser = subparsers.add_parser(
        "read",
        help="Grant read ACL to a user or group on PATH.",
        parents=[common_opts],
    )
    read_parser.add_argument("path", help="Local path under NFS mount")
    read_parser.add_argument("subject", help="LOGIN or GROUP (use @group to force group)")

    readwrite_parser = subparsers.add_parser(
        "readwrite",
        help="Grant read-write ACL to a user or group on PATH.",
        parents=[common_opts],
    )
    readwrite_parser.add_argument("path", help="Local path under NFS mount")
    readwrite_parser.add_argument("subject", help="LOGIN or GROUP (use @group to force group)")

    undo_parser = subparsers.add_parser(
        "undo",
        help="Remove ACL entries for a user or group from PATH.",
        parents=[common_opts],
    )
    undo_parser.add_argument("path", help="Local path under NFS mount")
    undo_parser.add_argument("subject", help="LOGIN or GROUP (use @group to force group)")
    undo_parser.add_argument(
        "-p",
        "--parent",
        action="store_true",
        help="Also remove ACLs from parent directories (DANGEROUS)",
    )

    show_parser = subparsers.add_parser(
        "show",
        help="Show current ACLs for PATH.",
        parents=[common_opts],
    )
    show_parser.add_argument("path", help="Local path under NFS mount")

    subparsers.add_parser(
        "list",
        help="List ACL changes recorded in ~/.shared_dirs.",
        parents=[common_opts],
    )
    return parser


def main() -> int:
    ap = build_arg_parser()
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.action == "list":
        return handle_list()

    p = Path(args.path).expanduser().resolve()
    if not is_path_allowed(p):
        log.error(f"Path '{p}' is not allowed. Allowed roots: {SHARE_DIR_ALLOWED_ROOTS}")
        return 3

    mounts = parse_proc_mounts()
    mount = find_nfs_mount_for_path(args.path, mounts)
    if not mount:
        log.error("ERROR: PATH is not on an NFS mount")
        return 2

    if args.action == "show":
        return handle_show(args, mount.server, local_to_remote_path(args.path, mount))

    if args.action in ("read", "readwrite"):
        return handle_read_readwrite(args, mount)

    if args.action == "undo":
        return handle_undo(args, mount)

    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
