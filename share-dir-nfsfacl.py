#!/usr/bin/env python3
"""share-dir-nfsfacl: manage POSIX ACL sharing on NFS homes via getfacl/setfacl over SSH.

Why this exists
--------------
Some environments mount /home via NFS and do not allow ACL changes from the client
(or do not have the tooling available in the server-side jail/chroot). This tool
runs *only* standard ACL utilities on the NFS server:
  - getfacl
  - setfacl

It detects the NFS server for PATH on the client, translates the PATH to the
server-local filesystem path, and then executes getfacl/setfacl remotely via SSH.

USAGE
-----
  share-dir-nfsfacl [-r] [-n] read PATH SUBJECT [SUBJECT...]
  share-dir-nfsfacl [-r] [-n] readwrite PATH SUBJECT [SUBJECT...]
  share-dir-nfsfacl [-n] undo [-p] PATH
  share-dir-nfsfacl show PATH
  share-dir-nfsfacl list [-H]

SUBJECT
-------
  - u:LOGIN   explicit user
  - g:GROUP   explicit group
  - LOGIN     autodetect (user first, then group)

RECURSION
---------
  - Without -r, the operation affects:
      PATH and its direct children (maxdepth=1)
  - With -r, the operation affects:
      PATH and the whole subtree

UNDO
----
Undo restores the previous ACL state captured before the last read/readwrite
operation for PATH. The restore payload is captured using getfacl output and
applied back using setfacl --restore on the NFS server.

The optional -p/--parents for undo will also attempt to remove the SUBJECT entry
from parent directories (traverse ACLs). A warning is printed because this may
break other shares.

LOGGING
-------
Operations are logged to:
  ~/.shared_dirs
Each read/readwrite stores a restore payload (getfacl output) to allow undo.

REMOTE CONFIG
-------------
Environment variables:
  - SHARE_DIR_SSH:         ssh binary (default: ssh)
  - SHARE_DIR_SSH_OPTS:    extra ssh options (e.g. "-J jump")
  - SHARE_DIR_REMOTE_USER: ssh username (default: current user)

Allowed roots (guardrail on the *client path*):
  - SHARE_DIR_ALLOWED_ROOTS="/home;/tmp;/data;/storage;/projects"  (semicolon-separated)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import pwd
import grp
import platform
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


LOG = logging.getLogger("share-dir-nfsfacl")



def _cmd_str(cmd: List[str]) -> str:
    try:
        return shlex.join(cmd)
    except AttributeError:
        return " ".join(shlex.quote(c) for c in cmd)


def _current_user() -> str:
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "") or "root"


# ----------------------------
# Data models and logging
# ----------------------------


@dataclass(frozen=True)
class Subject:
    kind: str  # user/group
    name: str


@dataclass
class OperationRecord:
    ts: str
    host: str
    actor: str
    action: str  # read/readwrite/undo
    path: str  # local path (resolved)
    server: Optional[str]
    server_path: Optional[str]
    subject_kind: Optional[str]
    subject: Optional[str]
    recurse: bool
    restore_text: Optional[str]  # getfacl output for setfacl --restore


def log_file() -> Path:
    return Path.home() / ".shared_dirs"


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def actor_name() -> str:
    return _current_user()


def write_log(record: OperationRecord) -> None:
    lf = log_file()
    lf.parent.mkdir(parents=True, exist_ok=True)
    with lf.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")


def find_last_record_for_path(path: Path) -> Optional[OperationRecord]:
    lf = log_file()
    if not lf.exists():
        return None

    target = str(path.resolve())
    last = None
    fields = set(OperationRecord.__dataclass_fields__.keys())

    with lf.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("path") == target and obj.get("action") in ("read", "readwrite"):
                data = {k: v for k, v in obj.items() if k in fields}
                last = OperationRecord(**data)
    return last


# ----------------------------
# Subject parsing
# ----------------------------


def resolve_subject(raw: str) -> Subject:
    raw = raw.strip()

    if raw.startswith("u:"):
        name = raw[2:]
        pwd.getpwnam(name)
        return Subject(kind="user", name=name)

    if raw.startswith("g:"):
        name = raw[2:]
        grp.getgrnam(name)
        return Subject(kind="group", name=name)

    # autodetect: try user then group
    try:
        pwd.getpwnam(raw)
        return Subject(kind="user", name=raw)
    except KeyError:
        pass

    try:
        grp.getgrnam(raw)
        return Subject(kind="group", name=raw)
    except KeyError:
        raise SystemExit(f"SUBJECT '{raw}' is neither a user nor a group (use u:LOGIN or g:GROUP).")


# ----------------------------
# Client-side mount detection and path translation
# ----------------------------


def _run_local(cmd: List[str]) -> str:
    p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return p.stdout.strip()


def parse_allowed_roots() -> List[Path]:
    raw = os.environ.get("SHARE_DIR_ALLOWED_ROOTS", f"{Path.home()};/tmp;/data;/storage;/projects")
    roots: List[Path] = []
    for part in raw.split(";"):
        part = part.strip()
        if part:
            roots.append(Path(part).resolve())
    return roots


def _is_under_any_root(target: Path, roots: List[Path]) -> Optional[Path]:
    t = target.resolve()
    for r in roots:
        try:
            t.relative_to(r)
            return r
        except ValueError:
            continue
    return None


def find_nfs_mount_info(path: Path) -> Tuple[str, Path, Path, Path]:
    """Return (server, mount_target, export_path, server_path_for_input)."""
    out = _run_local(["findmnt", "-n", "-o", "SOURCE,TARGET,FSTYPE", "-T", str(path)])
    if not out:
        raise SystemExit(f"Could not determine mount for: {path}")

    parts = out.split()
    if len(parts) < 3:
        raise SystemExit(f"Unexpected findmnt output for {path!s}: {out!r}")

    source, target, fstype = parts[0], parts[1], parts[2]
    if not fstype.startswith("nfs"):
        raise SystemExit(f"Path {path} is on filesystem type '{fstype}', not NFS.")
    if ":" not in source:
        raise SystemExit(f"Unexpected NFS SOURCE format (expected server:/export): {source}")

    server, export = source.split(":", 1)
    mount_target = Path(target).resolve()

    input_path = path.resolve()
    try:
        rel = input_path.relative_to(mount_target)
    except ValueError:
        rel = Path(os.path.relpath(str(input_path), str(mount_target)))

    export_path = Path(export)
    server_path = export_path if str(rel) == "." else (export_path / rel)
    return server, mount_target, export_path, server_path


def iter_parents_from_root(target: Path, root: Path) -> Iterable[Path]:
    target = target.resolve()
    root = root.resolve()
    parent = target if target.is_dir() else target.parent
    rel = parent.relative_to(root)
    cur = root
    yield cur
    for part in rel.parts:
        cur = cur / part
        yield cur


# ----------------------------
# Remote execution
# ----------------------------


def ssh_base(server: str) -> List[str]:
    ssh_bin = os.environ.get("SHARE_DIR_SSH", "ssh")
    ssh_opts = shlex.split(os.environ.get("SHARE_DIR_SSH_OPTS", ""))
    remote_user = os.environ.get("SHARE_DIR_REMOTE_USER", _current_user())
    ssh_target = f"{remote_user}@{server}" if remote_user else server
    return [ssh_bin, *ssh_opts, ssh_target, "--"]


def run_remote(
    server: str,
    remote_cmd: List[str],
    *,
    input_text: Optional[str] = None,
    dry_run: bool = False,
) -> subprocess.CompletedProcess:
    """Run a remote command via SSH, optionally as a dry-run (no execution)."""
    cmd = ssh_base(server) + remote_cmd
    LOG.info("SSH: %s", _cmd_str(cmd))

    if dry_run:
        LOG.warning("DRY RUN (-n): SSH command will NOT be executed.")
        if input_text:
            LOG.info("DRY RUN would send %d bytes on stdin", len(input_text.encode("utf-8")))
        print(_cmd_str(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    return subprocess.run(
        cmd,
        input=(input_text if input_text is not None else None),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def remote_check_ok(cp: subprocess.CompletedProcess, what: str) -> None:
    if cp.returncode != 0:
        raise SystemExit(f"Remote {what} failed (rc={cp.returncode}): {cp.stderr.strip()}")


# ----------------------------
# ACL operations via getfacl/setfacl
# ----------------------------


def remote_getfacl(
    server: str,
    server_path: str,
    recurse: bool,
    depth1: bool,
    *,
    dry_run: bool,
) -> str:
    # Use absolute names so --restore is unambiguous on the server.
    cmd = ["getfacl", "--absolute-names", "-p"]
    if recurse:
        cmd.append("-R")
    elif depth1:
        # emulate maxdepth=1 capture: PATH plus direct children
        # We do this with a remote shell pipeline so we can pass many paths to getfacl.
        # Implemented separately below.
        raise RuntimeError("depth1 capture should use remote_getfacl_depth1")
    cmd.append(server_path)

    cp = run_remote(server, cmd, dry_run=dry_run)
    remote_check_ok(cp, "getfacl")
    return cp.stdout


def remote_getfacl_depth1(server: str, server_path: str, *, dry_run: bool) -> str:
    # Capture PATH and direct children (maxdepth=1)
    # Using find -print0 and xargs -0 to handle special characters.
    sh = (
        f"set -e; "
        f"p={shlex.quote(server_path)}; "
        f"{{ printf '%s\0' \"$p\"; find \"$p\" -mindepth 1 -maxdepth 1 -print0; }} "
        f"| xargs -0 getfacl --absolute-names -p"
    )
    cp = run_remote(server, ["sh", "-lc", sh], dry_run=dry_run)
    remote_check_ok(cp, "getfacl")
    return cp.stdout


def remote_setfacl_restore(server: str, restore_text: str, *, dry_run: bool) -> None:
    # setfacl expects a restore file; we create a temp file on the server.
    # We do not assume scp is available; we stream via ssh stdin.
    tmp = f"/tmp/share-dir-restore.{os.getpid()}.{int(dt.datetime.now().timestamp())}"
    sh = (
        f"set -e; "
        f"umask 077; "
        f"cat > {shlex.quote(tmp)}; "
        f"setfacl --restore={shlex.quote(tmp)}; "
        f"rm -f {shlex.quote(tmp)}"
    )
    cp = run_remote(server, ["sh", "-lc", sh], input_text=restore_text, dry_run=dry_run)
    remote_check_ok(cp, "setfacl --restore")


def setfacl_spec(subject: Subject, perms: str) -> str:
    # perms are strings like r-x, rwx, r--, rw-
    prefix = "u" if subject.kind == "user" else "g"
    return f"{prefix}:{subject.name}:{perms}"


def setfacl_remove_spec(subject: Subject) -> str:
    prefix = "u" if subject.kind == "user" else "g"
    return f"{prefix}:{subject.name}"


def perms_for(path_is_dir: bool, action: str) -> str:
    if action == "read":
        return "r-x" if path_is_dir else "r--"
    if action == "readwrite":
        return "rwx" if path_is_dir else "rw-"
    raise ValueError(action)


def remote_apply_traverse_parents(server: str, server_path: str, subject: Subject, allowed_root_local: Path, target_local: Path, dry_run: bool) -> None:
    # Translate local parent directories to server paths using the same relative mapping.
    # allowed_root_local is a local Path root that contains target_local.
    rel_parent = (target_local if target_local.is_dir() else target_local.parent).relative_to(allowed_root_local)

    # We must also know the server path for the allowed root; since server_path corresponds to target_local,
    # derive server_root_path = server_path - rel_parent.
    server_path_obj = Path(server_path)
    server_root_path = server_path_obj
    for _ in rel_parent.parts:
        server_root_path = server_root_path.parent

    # Build list of server-side parent directories from server_root_path to parent(server_path)
    dirs: List[Path] = [server_root_path]
    cur = server_root_path
    for part in rel_parent.parts:
        cur = cur / part
        dirs.append(cur)

    spec = setfacl_spec(subject, "--x")

    for d in dirs:
        cmd = ["setfacl", "-m", spec, str(d)]
        if dry_run:
            LOG.info("[dry-run] would set traverse on %s", d)
            run_remote(server, cmd, dry_run=dry_run)  # prints cmd in dry-run mode
        else:
            cp = run_remote(server, cmd, dry_run=dry_run)
            remote_check_ok(cp, "setfacl -m (traverse)")


def remote_apply_share(server: str, server_path: str, subject: Subject, action: str, recurse: bool, dry_run: bool) -> None:
    # Apply access ACL
    perms_dir = perms_for(True, action)
    perms_file = perms_for(False, action)

    spec_dir = setfacl_spec(subject, perms_dir)
    spec_file = setfacl_spec(subject, perms_file)

    if recurse:
        # One setfacl for everything (directories and files) would be wrong for execute bit.
        # We therefore do two passes using find:
        sh = (
            f"set -e; p={shlex.quote(server_path)}; "
            f"find \"$p\" -type d -print0 | xargs -0 setfacl -m {shlex.quote(spec_dir)}; "
            f"find \"$p\" -type d -print0 | xargs -0 setfacl -d -m {shlex.quote(spec_dir)}; "
            f"find \"$p\" -type f -print0 | xargs -0 setfacl -m {shlex.quote(spec_file)}"
        )
        cp = run_remote(server, ["sh", "-lc", sh], dry_run=dry_run)
        remote_check_ok(cp, "setfacl (recursive)")
        return

    # depth1 (PATH + direct children)
    sh = (
        f"set -e; p={shlex.quote(server_path)}; "
        f"setfacl -m {shlex.quote(spec_dir)} \"$p\"; "
        f"if [ -d \"$p\" ]; then "
        f"  setfacl -d -m {shlex.quote(spec_dir)} \"$p\"; "
        f"  find \"$p\" -mindepth 1 -maxdepth 1 -type d -print0 | xargs -0 setfacl -m {shlex.quote(spec_dir)}; "
        f"  find \"$p\" -mindepth 1 -maxdepth 1 -type d -print0 | xargs -0 setfacl -d -m {shlex.quote(spec_dir)}; "
        f"  find \"$p\" -mindepth 1 -maxdepth 1 -type f -print0 | xargs -0 setfacl -m {shlex.quote(spec_file)}; "
        f"else "
        f"  :; "
        f"fi"
    )
    cp = run_remote(server, ["sh", "-lc", sh], dry_run=dry_run)
    remote_check_ok(cp, "setfacl (depth1)")


def remote_remove_parent_subject(server: str, server_dir: str, subject: Subject, dry_run: bool) -> None:
    # Remove only access entry (this is what traverse setting created)
    spec = setfacl_remove_spec(subject)
    cmd = ["setfacl", "-x", spec, server_dir]
    if dry_run:
        LOG.info("[dry-run] would remove ACL entry %s from %s", spec, server_dir)
        run_remote(server, cmd, dry_run=dry_run)
        return
    cp = run_remote(server, cmd, dry_run=dry_run)
    remote_check_ok(cp, "setfacl -x")


# ----------------------------
# CLI actions
# ----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Manage sharing ACLs on NFS via getfacl/setfacl over SSH")
    p.add_argument("-r", "--recurse", action="store_true", help="Recurse into subdirectories")
    p.add_argument("-n", "--dry-run", action="store_true", help="Dry run (do not change anything)")
    p.add_argument("-v", "--verbose", action="count", default=0)

    sub = p.add_subparsers(dest="cmd", required=True)

    for cmd in ("read", "readwrite"):
        sp = sub.add_parser(cmd)
        sp.add_argument("path")
        sp.add_argument("subject", nargs="+")

    spu = sub.add_parser("undo")
    spu.add_argument("-p", "--parents", action="store_true", help="Also remove SUBJECT entry from parent directories (use with care)")
    spu.add_argument("path")

    sps = sub.add_parser("show")
    sps.add_argument("path")

    spl = sub.add_parser("list")
    spl.add_argument("-H", "--no-header", action="store_true", help="Do not print header row")

    return p


def configure_logging(verbose: int) -> None:
    """Configure logging based solely on -v / -vv flags."""
    level = logging.WARNING
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")


def action_list(no_header: bool) -> None:
    lf = log_file()
    if not lf.exists():
        print("No log file found")
        return

    if not no_header:
        print(f"{'PATH':<50} {'ACTION':<10} {'SUBJECT':<20} {'SERVER':<25}")
        print(f"{'-'*50} {'-'*10} {'-'*20} {'-'*25}")

    seen: Dict[str, Dict[str, Any]] = {}
    with lf.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("action") in ("read", "readwrite"):
                seen[obj["path"]] = obj

    for path, rec in sorted(seen.items()):
        subj = f"{rec.get('subject_kind')}:{rec.get('subject')}"
        srv = rec.get("server") or ""
        print(f"{path:<50} {rec['action']:<10} {subj:<20} {srv:<25}")


def action_show(local_path: Path) -> None:
    roots = parse_allowed_roots()
    if _is_under_any_root(local_path, roots) is None:
        raise SystemExit(f"Path {local_path} is not under allowed roots: {', '.join(str(r) for r in roots)}")

    server, _, _, server_path = find_nfs_mount_info(local_path)
    # show ACL only for the specific object
    txt = remote_getfacl(server, str(server_path), recurse=False, depth1=False, dry_run=False)
    print(txt, end="" if txt.endswith("\n") else "\n")

    rec = find_last_record_for_path(local_path)
    if rec:
        print("# Last operation")
        print(json.dumps(rec.__dict__, indent=2, ensure_ascii=False))


def action_read_or_readwrite(local_path: Path, subjects: List[Subject], action: str, recurse: bool, dry_run: bool) -> None:
    roots = parse_allowed_roots()
    root = _is_under_any_root(local_path, roots)
    if root is None:
        raise SystemExit(f"Path {local_path} is not under allowed roots: {', '.join(str(r) for r in roots)}")

    if local_path.is_symlink():
        raise SystemExit("Target path is a symlink; refusing for safety reasons.")

    server, mount_target, export_path, server_path = find_nfs_mount_info(local_path)

    LOG.info("NFS mount: %s is on %s:%s mounted at %s", local_path, server, export_path, mount_target)
    LOG.info("Translated server path: %s", server_path)

    # Capture restore payload once per operation (covers PATH and affected subtree)
    if recurse:
        restore_text = remote_getfacl(server, str(server_path), recurse=True, depth1=False, dry_run=dry_run)
    else:
        restore_text = remote_getfacl_depth1(server, str(server_path), dry_run=dry_run)

    # Apply per-subject
    for subject in subjects:
        # Ensure traverse (+x) on parent directories (access ACL)
        remote_apply_traverse_parents(
            server,
            str(server_path),
            subject,
            allowed_root_local=root,
            target_local=local_path,
            dry_run=dry_run,
        )

        # Apply sharing ACLs on PATH/subtree
        remote_apply_share(server, str(server_path), subject, action=action, recurse=recurse, dry_run=dry_run)

        if not dry_run:
            write_log(
                OperationRecord(
                    ts=now_iso(),
                    host=platform.node(),
                    actor=actor_name(),
                    action=action,
                    path=str(local_path.resolve()),
                    server=server,
                    server_path=str(server_path),
                    subject_kind=subject.kind,
                    subject=subject.name,
                    recurse=bool(recurse),
                    restore_text=restore_text,
                )
            )


def action_undo(local_path: Path, parents: bool, dry_run: bool) -> None:
    rec = find_last_record_for_path(local_path)
    if rec is None or not rec.restore_text:
        raise SystemExit(f"No undo data found in log for {local_path}")

    if not rec.server or not rec.server_path:
        raise SystemExit(f"Log record for {local_path} does not contain server mapping")

    if parents:
        LOG.warning(
            "UNDO WITH -p/--parents: parent directories will be modified (subject ACL entries will be removed). "
            "This may break other shares if they rely on the same traverse ACL."
        )

    # Restore previous ACL state
    remote_setfacl_restore(rec.server, rec.restore_text, dry_run=dry_run)

    # Optionally remove traverse entry from parent directories
    if parents:
        if not rec.subject_kind or not rec.subject:
            raise SystemExit("Cannot apply -p: missing subject information in log")
        subject = resolve_subject(("u:" if rec.subject_kind == "user" else "g:") + rec.subject)

        # Recompute parents based on current local path and allowed roots
        roots = parse_allowed_roots()
        root = _is_under_any_root(local_path, roots)
        if root is None:
            raise SystemExit(f"Path {local_path} is not under allowed roots: {', '.join(str(r) for r in roots)}")

        # Derive server root path similarly to remote_apply_traverse_parents
        local_parent_rel = (local_path if local_path.is_dir() else local_path.parent).relative_to(root)
        server_path_obj = Path(rec.server_path)
        server_root_path = server_path_obj
        for _ in local_parent_rel.parts:
            server_root_path = server_root_path.parent

        dirs: List[Path] = [server_root_path]
        cur = server_root_path
        for part in local_parent_rel.parts:
            cur = cur / part
            dirs.append(cur)

        for d in dirs:
            remote_remove_parent_subject(rec.server, str(d), subject, dry_run=dry_run)

    if not dry_run:
        write_log(
            OperationRecord(
                ts=now_iso(),
                host=platform.node(),
                actor=actor_name(),
                action="undo",
                path=str(local_path.resolve()),
                server=rec.server,
                server_path=rec.server_path,
                subject_kind=None,
                subject=None,
                recurse=False,
                restore_text=None,
            )
        )


def main() -> None:
    args = build_parser().parse_args()
    configure_logging(args.verbose)

    if args.cmd == "list":
        action_list(no_header=bool(args.no_header))
        return

    local_path = Path(getattr(args, "path", "")).expanduser().resolve()

    if args.cmd == "show":
        action_show(local_path)
        return

    if args.cmd in ("read", "readwrite"):
        subjects = [resolve_subject(s) for s in args.subject]
        action_read_or_readwrite(local_path, subjects, action=args.cmd, recurse=bool(args.recurse), dry_run=bool(args.dry_run))
        return

    if args.cmd == "undo":
        action_undo(local_path, parents=bool(args.parents), dry_run=bool(args.dry_run))
        return


if __name__ == "__main__":
    main()
