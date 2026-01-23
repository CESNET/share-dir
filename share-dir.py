#!/usr/bin/env python3
"""
share-dir: manage POSIX ACL (extended ACL) for sharing directories/files.

Usage:
  share-dir [-r] [--dry-run] read|readwrite PATH SUBJECT
  share-dir [--dry-run] undo PATH

SUBJECT:
  - "u:login" or "g:group" (recommended), or
  - without prefix -> autodetection: first user, then group

Security:
  - traverse (+x) is applied only under allowed roots.
    Configure via env SHARE_DIR_ALLOWED_ROOTS="/data;/storage;/projects"
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import json
import logging
import os
import platform
import pwd
import grp
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import posix1e  # pylibacl


LOG = logging.getLogger("share-dir")


def log_action(dry_run: bool, message: str) -> None:
    """Log an action, prefixing with [dry-run] when applicable."""
    LOG.debug(f"{'[dry-run] ' if dry_run else ''}{message}")


# ----------------------------
# Data models
# ----------------------------

@dataclass(frozen=True)
class Subject:
    """Represents a user or group ACL subject."""
    kind: str  # "user" or "group"
    name: str
    uid_or_gid: int


@dataclass
class AclStateItem:
    """Stores ACL state of a filesystem object."""
    path: str
    is_dir: bool
    access_acl_text: str
    default_acl_text: Optional[str]  # only for directories


@dataclass
class OperationRecord:
    """Single audit/log record."""
    ts: str
    host: str
    actor: str
    action: str  # read/readwrite/undo
    path: str
    subject_kind: Optional[str]
    subject: Optional[str]
    recurse: bool
    acl_items: Optional[List[Dict[str, Any]]]


# ----------------------------
# Subject resolution
# ----------------------------


def resolve_subject(raw: str) -> Subject:
    """Resolve SUBJECT to user or group (explicit or autodetected)."""
    raw = raw.strip()

    if raw.startswith("u:"):
        name = raw[2:]
        pw = pwd.getpwnam(name)
        return Subject(kind="user", name=name, uid_or_gid=pw.pw_uid)

    if raw.startswith("g:"):
        name = raw[2:]
        gr = grp.getgrnam(name)
        return Subject(kind="group", name=name, uid_or_gid=gr.gr_gid)

    # autodetect: try user first, then group
    try:
        pw = pwd.getpwnam(raw)
        return Subject(kind="user", name=raw, uid_or_gid=pw.pw_uid)
    except KeyError:
        pass

    try:
        gr = grp.getgrnam(raw)
        return Subject(kind="group", name=raw, uid_or_gid=gr.gr_gid)
    except KeyError:
        raise SystemExit(
            f"SUBJECT '{raw}' is neither a user nor a group. Use u:LOGIN or g:GROUP."
        )


# ----------------------------
# ACL helpers
# ----------------------------


def _acl_from_path_access(path: Path) -> posix1e.ACL:
    """Load access ACL from path."""
    return posix1e.ACL(file=str(path))


def _acl_from_path_default(path: Path) -> posix1e.ACL:
    """Load default ACL from directory (if any)."""
    return posix1e.ACL(filedef=str(path))


def _acl_to_text(acl: posix1e.ACL) -> str:
    """Serialize ACL to text form."""
    return str(acl)


def _acl_from_text(text: str) -> posix1e.ACL:
    """Deserialize ACL from text form."""
    return posix1e.ACL(text=text)


def _find_entry(
    acl: posix1e.ACL, tag_type: int, qualifier: Optional[int]
) -> Optional[posix1e.Entry]:
    """Find ACL entry by tag type and qualifier."""
    for e in acl:
        if e.tag_type != tag_type:
            continue
        if qualifier is None:
            return e
        try:
            if e.qualifier == qualifier:
                return e
        except (AttributeError, OSError):
            continue
    return None


def _ensure_entry(
    acl: posix1e.ACL, tag_type: int, qualifier: Optional[int]
) -> posix1e.Entry:
    """Get or create ACL entry."""
    e = _find_entry(acl, tag_type, qualifier)
    if e is not None:
        return e
    e = posix1e.Entry(acl)
    e.tag_type = tag_type
    if qualifier is not None:
        e.qualifier = qualifier
    acl.append(e)
    return e


def _permset_set(
    ps: posix1e.Permset,
    r: Optional[bool],
    w: Optional[bool],
    x: Optional[bool],
    widen_only: bool,
) -> None:
    """
    Modify permission set.

    If widen_only=True: only add permissions, never remove.
    If widen_only=False: explicitly set permissions when provided.
    """
    if widen_only:
        if r:
            ps.read = True
        if w:
            ps.write = True
        if x:
            ps.execute = True
        return

    if r is not None:
        ps.read = bool(r)
    if w is not None:
        ps.write = bool(w)
    if x is not None:
        ps.execute = bool(x)


def _ensure_base_entries(acl: posix1e.ACL, path: Path) -> None:
    """Ensure ACL has required base entries (user/group/other)."""
    st = path.stat()
    want = {
        posix1e.ACL_USER_OBJ: (
            bool(st.st_mode & stat.S_IRUSR),
            bool(st.st_mode & stat.S_IWUSR),
            bool(st.st_mode & stat.S_IXUSR),
        ),
        posix1e.ACL_GROUP_OBJ: (
            bool(st.st_mode & stat.S_IRGRP),
            bool(st.st_mode & stat.S_IWGRP),
            bool(st.st_mode & stat.S_IXGRP),
        ),
        posix1e.ACL_OTHER: (
            bool(st.st_mode & stat.S_IROTH),
            bool(st.st_mode & stat.S_IWOTH),
            bool(st.st_mode & stat.S_IXOTH),
        ),
    }
    for tag_type, perms in want.items():
        e = _find_entry(acl, tag_type, None)
        if e is None:
            e = posix1e.Entry(acl)
            e.tag_type = tag_type
            acl.append(e)
            _permset_set(e.permset, r=perms[0], w=perms[1], x=perms[2], widen_only=False)


def _dedupe_acl(acl: posix1e.ACL) -> None:
    """Remove duplicate entries so ACL validates cleanly."""
    seen = set()
    for e in list(acl):
        key = (e.tag_type, None)
        if e.tag_type in (posix1e.ACL_USER, posix1e.ACL_GROUP):
            try:
                key = (e.tag_type, e.qualifier)
            except (AttributeError, OSError):
                key = (e.tag_type, None)
        if key in seen:
            acl.delete_entry(e)
            continue
        seen.add(key)


def _set_named_acl(
    path: Path,
    subject: Subject,
    perms: Tuple[bool, bool, bool],
    is_default: bool,
    dry_run: bool,
) -> None:
    """
    Apply ACL for a named user/group on a single filesystem object.
    Also widens mask permissions if required.
    """
    r, w, x = perms

    acl = (
        _acl_from_path_default(path)
        if is_default
        else _acl_from_path_access(path)
    )

    tag = posix1e.ACL_USER if subject.kind == "user" else posix1e.ACL_GROUP

    entry = _ensure_entry(acl, tag, subject.uid_or_gid)
    _permset_set(entry.permset, r=r, w=w, x=x, widen_only=False)

    # Ensure mask allows required permissions
    mask_entry = _ensure_entry(acl, posix1e.ACL_MASK, None)
    _permset_set(mask_entry.permset, r=r, w=w, x=x, widen_only=True)

    try:
        acl.calc_mask()
    except Exception:
        # Mask calculation may fail on unusual ACLs; mask already widened.
        pass

    _dedupe_acl(acl)

    log_action(
        dry_run,
        f"apply {'default' if is_default else 'access'} ACL to {path}: {subject}",
    )
    if dry_run:
        return

    _apply_acl(path, acl, is_default=is_default)


def _delete_named_acl_entry(
    path: Path,
    subject: Subject,
    is_default: bool,
    dry_run: bool,
) -> None:
    """Delete a named user/group ACL entry from a path."""
    acl = _acl_from_path_default(path) if is_default else _acl_from_path_access(path)

    tag = posix1e.ACL_USER if subject.kind == "user" else posix1e.ACL_GROUP
    entry = _find_entry(acl, tag, subject.uid_or_gid)
    if entry is None:
        return

    log_action(
        dry_run,
        f"delete {'default' if is_default else 'access'} ACL entry on {path}: {subject}",
    )
    if dry_run:
        return

    try:
        acl.delete_entry(entry)
    except Exception:
        # Fallback for older builds
        try:
            acl.remove(entry)
        except Exception:
            return

    try:
        acl.calc_mask()
    except Exception:
        pass

    _dedupe_acl(acl)
    _apply_acl(path, acl, is_default=is_default)


def _restore_acl_text(
    path: Path,
    access_text: str,
    default_text: Optional[str],
    dry_run: bool,
) -> None:
    """Restore access and default ACL from serialized text."""
    log_action(dry_run, f"restore ACL on {path}")
    if dry_run:
        return

    access_acl = _acl_from_text(access_text)
    _apply_acl(path, access_acl, is_default=False)

    if default_text is not None:
        default_acl = _acl_from_text(default_text)
        _apply_acl(path, default_acl, is_default=True)


def _apply_acl(path: Path, acl: posix1e.ACL, is_default: bool) -> None:
    """Apply ACL and surface a clear error if the filesystem lacks ACL support."""
    _ensure_base_entries(acl, path)
    _dedupe_acl(acl)
    try:
        is_valid = acl.valid()
    except Exception:
        is_valid = None
    if is_valid is False:
        raise SystemExit(
            f"Generated ACL is invalid for '{path}'. "
            f"ACL={acl.to_any_text()}"
        )
    try:
        if is_default:
            acl.applyto(str(path), posix1e.ACL_TYPE_DEFAULT)
        else:
            acl.applyto(str(path))
    except OSError as e:
        if e.errno == errno.EINVAL:
            raise SystemExit(
                f"ACL apply failed for '{path}' (EINVAL). "
                "This can mean an invalid ACL or a filesystem without POSIX ACL support. "
                f"ACL={acl.to_any_text()}"
            )
        raise


# ----------------------------
# Guardrails: allowed roots and traversal
# ----------------------------


def parse_allowed_roots() -> List[Path]:
    """Parse allowed root directories from environment."""
    raw = os.environ.get("SHARE_DIR_ALLOWED_ROOTS", f"{Path.home()};/tmp;/data;/storage;/projects")
    roots = []
    for part in raw.split(";"):
        part = part.strip()
        if part:
            roots.append(Path(part).resolve())
    return roots


def _is_under_any_root(target: Path, roots: List[Path]) -> Optional[Path]:
    """Check whether target is under one of the allowed roots."""
    t = target.resolve()
    for r in roots:
        try:
            t.relative_to(r)
            return r
        except ValueError:
            continue
    return None


def iter_parents_from_root(target: Path, root: Path) -> Iterable[Path]:
    """
    Yield directories from root up to the parent of target.
    Example: /data/a/b/file -> /data, /data/a, /data/a/b
    """
    target = target.resolve()
    root = root.resolve()

    parent = target if target.is_dir() else target.parent
    rel = parent.relative_to(root)
    current = root
    yield current
    for part in rel.parts:
        current = current / part
        yield current


def ensure_traverse_x(
    target: Path, subject: Subject, roots: List[Path], dry_run: bool
) -> None:
    """Ensure execute (traverse) permission on all parent directories."""
    root = _is_under_any_root(target, roots)
    if root is None:
        raise SystemExit(
            f"Path {target} is not under allowed roots: "
            f"{', '.join(str(r) for r in roots)}"
        )

    for d in iter_parents_from_root(target, root):
        _set_named_acl(d, subject, perms=(False, False, True), is_default=False, dry_run=dry_run)


# ----------------------------
# Logging
# ----------------------------


def log_file() -> Path:
    """Return path to main audit log."""
    return Path.home() / ".shared_dirs"


def actor_name() -> str:
    """Return current user name."""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return str(os.getuid())


def now_iso() -> str:
    """Current timestamp with timezone."""
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def write_log(record: OperationRecord) -> None:
    """Append operation record to audit log."""
    lf = log_file()
    lf.parent.mkdir(parents=True, exist_ok=True)
    with lf.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record.__dict__, ensure_ascii=False) + "\n")


def capture_acl_state(target: Path, recurse: bool) -> List[AclStateItem]:
    """Capture ACL state for target (and optionally subtree)."""
    items: List[AclStateItem] = []

    def snap_one(p: Path) -> None:
        is_dir = p.is_dir()
        access = _acl_to_text(_acl_from_path_access(p))
        default = None
        if is_dir:
            try:
                default = _acl_to_text(_acl_from_path_default(p))
            except Exception:
                default = None
        items.append(
            AclStateItem(
                path=str(p),
                is_dir=is_dir,
                access_acl_text=access,
                default_acl_text=default,
            )
        )

    if target.is_dir():
        snap_one(target)
        if recurse:
            for p in target.rglob("*"):
                if not p.is_symlink():
                    snap_one(p)
        else:
            for p in target.iterdir():
                if not p.is_symlink():
                    snap_one(p)
    else:
        snap_one(target)

    return items


def find_last_record_for_path(path: Path) -> Optional[OperationRecord]:
    """Find last read/readwrite operation for given path."""
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
            except json.JSONDecodeError:
                continue
            if obj.get("path") == target and obj.get("action") in ("read", "readwrite"):
                data = {k: v for k, v in obj.items() if k in fields}
                if "acl_items" not in data:
                    data["acl_items"] = None
                last = OperationRecord(**data)
    return last


# ----------------------------
# Apply and undo operations
# ----------------------------


def perms_for(path: Path, action: str) -> Tuple[bool, bool, bool]:
    """Return permission tuple (r,w,x) based on path type and action."""
    is_dir = path.is_dir()
    if action == "read":
        return (True, False, True) if is_dir else (True, False, False)
    if action == "readwrite":
        return (True, True, True) if is_dir else (True, True, False)
    raise ValueError(action)


def apply_share(
    target: Path, subject: Subject, action: str, recurse: bool, dry_run: bool
) -> None:
    """Apply sharing ACL rules."""
    roots = parse_allowed_roots()

    if target.is_symlink():
        raise SystemExit("Target path is a symlink; refusing for safety reasons.")

    # Ensure traverse (+x) on parent directories
    ensure_traverse_x(target, subject, roots, dry_run=dry_run)

    def apply_one(p: Path) -> None:
        if p.is_symlink():
            return
        p_perms = perms_for(p, action)
        _set_named_acl(p, subject, perms=p_perms, is_default=False, dry_run=dry_run)
        if p.is_dir():
            _set_named_acl(p, subject, perms=p_perms, is_default=True, dry_run=dry_run)

    if target.is_dir():
        apply_one(target)
        if recurse:
            for p in target.rglob("*"):
                apply_one(p)
        else:
            for p in target.iterdir():
                apply_one(p)
    else:
        apply_one(target)


def do_undo(target: Path, dry_run: bool, parents: bool) -> None:
    """Undo last sharing operation for target.

    If parents=True, also walk parent directories of PATH (within allowed roots)
    and remove the SUBJECT entries that were added to enable traversal.

    WARNING: This can break other shares if they rely on the same traverse ACL.
    """
    rec = find_last_record_for_path(target)
    if rec is None or not rec.acl_items:
        raise SystemExit(f"No undo data found in log for {target}")

    if not rec.subject_kind or not rec.subject:
        raise SystemExit(f"Undo requires subject data in log record for {target}")

    subject = resolve_subject(("u:" if rec.subject_kind == "user" else "g:") + rec.subject)

    if parents:
        LOG.warning(
            "UNDO WITH -p/--parents: parent directories will be modified (subject ACL entries will be removed). "
            "This may break other shares if they rely on the same traverse ACL."
        )

    items = [AclStateItem(**x) for x in rec.acl_items]
    items.sort(key=lambda x: (0 if x.is_dir else 1, x.path))

    for item in items:
        p = Path(item.path)
        if p.exists():
            _restore_acl_text(p, item.access_acl_text, item.default_acl_text, dry_run=dry_run)

    if parents:
        roots = parse_allowed_roots()
        root = _is_under_any_root(target, roots)
        if root is None:
            raise SystemExit(
                f"Path {target} is not under allowed roots: {', '.join(str(r) for r in roots)}"
            )
        for d in iter_parents_from_root(target, root):
            _delete_named_acl_entry(d, subject, is_default=False, dry_run=dry_run)

    if not dry_run:
        write_log(
            OperationRecord(
                ts=now_iso(),
                host=platform.node(),
                actor=actor_name(),
                action="undo",
                path=str(target.resolve()),
                subject_kind=None,
                subject=None,
                recurse=False,
                acl_items=None,
            )
        )


# ----------------------------
# CLI
# ----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Set POSIX ACL sharing rules (pylibacl).")
    p.add_argument("-r", "--recurse", action="store_true", help="Recurse into subdirectories")
    p.add_argument("-n", "--dry-run", action="store_true", help="Dry run (do not change anything)")
    p.add_argument("-v", "--verbose", action="count", default=0)

    sub = p.add_subparsers(dest="cmd", required=True)

    # show: display ACL and last log record for path
    sps = sub.add_parser("show", help="Show ACL and last operation for PATH")
    sps.add_argument("path")

    # list: list all logged shared directories
    spl = sub.add_parser("list", help="List all shared directories from log")
    spl.add_argument(
        "-H",
        "--no-header",
        action="store_true",
        help="Do not print header row",
    )

    for cmd in ("read", "readwrite"):
        sp = sub.add_parser(cmd)
        sp.add_argument("path")
        sp.add_argument("subject", nargs="+")

    spu = sub.add_parser("undo")
    spu.add_argument(
        "-p",
        "--parents",
        action="store_true",
        help="Also remove SUBJECT entries from parent directories (use with care)",
    )
    spu.add_argument("path")

    return p


def main() -> None:
    args = build_parser().parse_args()

    level = logging.INFO
    if args.verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s")

    target = None
    if args.cmd in ("read", "readwrite", "show", "undo"):
        target = Path(args.path).expanduser().resolve()

    if args.cmd in ("read", "readwrite"):
        subjects = [resolve_subject(s) for s in args.subject]

        acl_items = capture_acl_state(target, recurse=args.recurse)
        acl_payload = [item.__dict__ for item in acl_items]

        for subject in subjects:
            apply_share(target, subject, action=args.cmd, recurse=args.recurse, dry_run=args.dry_run)

            if not args.dry_run:
                write_log(
                    OperationRecord(
                        ts=now_iso(),
                        host=platform.node(),
                        actor=actor_name(),
                        action=args.cmd,
                        path=str(target.resolve()),
                        subject_kind=subject.kind,
                        subject=subject.name,
                        recurse=bool(args.recurse),
                        acl_items=acl_payload,
                    )
                )

    elif args.cmd == "show":
        p = target
        print(f"# ACL for {p}")
        try:
            print(_acl_to_text(_acl_from_path_access(p)))
            if p.is_dir():
                try:
                    print("# Default ACL")
                    print(_acl_to_text(_acl_from_path_default(p)))
                except Exception:
                    pass
        except Exception as e:
            print(f"Failed to read ACL: {e}")

        rec = find_last_record_for_path(p)
        if rec:
            print("# Last operation")
            print(json.dumps(rec.__dict__, indent=2, ensure_ascii=False))
        else:
            print("# No previous operation found")

    elif args.cmd == "list":
        lf = log_file()
        if not lf.exists():
            print("No log file found")
        else:
            if not args.no_header:
                print(f"{'PATH':<50} {'ACTION':<10} {'SUBJECT':<20}")
                print(f"{'-'*50} {'-'*10} {'-'*20}")
            seen = {}
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
                print(f"{path:<50} {rec['action']:<10} {subj:<20}")

    elif args.cmd == "undo":
        do_undo(target, dry_run=args.dry_run, parents=bool(args.parents))


if __name__ == "__main__":
    main()
