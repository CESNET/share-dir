"""Tests for share-dir-nfsfacl.py.

The suite is intentionally safe to run as an ordinary user.  Filesystem tests
create their data below ``~/nfsacl-test/share-dir-nfsfacl-tests`` and all commands
which could contact an NFS server or modify ACLs are mocked.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "share-dir-nfsfacl.py"


def load_tool() -> types.ModuleType:
    """Load a script whose filename cannot be imported as a Python module."""
    spec = importlib.util.spec_from_file_location("share_dir_nfsfacl", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = load_tool()


class HomeDirectoryTestCase(unittest.TestCase):
    """Provide a private, disposable test tree in the invoking user's home."""

    @classmethod
    def setUpClass(cls) -> None:
        cache_root = Path(
            os.environ.get(
                "SHARE_DIR_TEST_BASE",
                Path.home() / "nfsacl-test" / "share-dir-nfsfacl-tests",
            )
        ).expanduser()
        cache_root.mkdir(parents=True, exist_ok=True)
        # NFS homes may be exposed through an alias such as /storage while
        # realpath() returns the autofs path under /auto.  The tool deliberately
        # canonicalizes paths, so fixtures and expected values must do the same.
        cls.cache_root = cache_root.resolve()

    def setUp(self) -> None:
        self.test_root = Path(
            tempfile.mkdtemp(prefix="case-", dir=self.cache_root)
        ).resolve()

    def tearDown(self) -> None:
        shutil.rmtree(self.test_root)


class PathMappingTests(HomeDirectoryTestCase):
    def test_longest_nfs_mount_wins(self) -> None:
        nested = self.test_root / "project"
        nested.mkdir()
        mounts = [
            tool.NfsMount(str(nested), "nested.example", "/exports/project"),
            tool.NfsMount(str(self.test_root), "home.example", "/exports/home"),
        ]

        mount = tool.find_nfs_mount_for_path(str(nested / "file"), mounts)

        self.assertEqual(mount, mounts[0])

    def test_local_path_is_mapped_below_export(self) -> None:
        target = self.test_root / "share" / "report.txt"
        mount = tool.NfsMount(str(self.test_root), "nfs.example", "/srv/users/test")

        remote = tool.local_to_remote_path(str(target), mount)

        self.assertEqual(remote, "/srv/users/test/share/report.txt")

    def test_allowed_root_rejects_root_itself_and_sibling_prefix(self) -> None:
        allowed = self.test_root / "allowed"
        allowed.mkdir()
        sibling = self.test_root / "allowed-elsewhere"
        sibling.mkdir()
        old_roots = tool.SHARE_DIR_ALLOWED_ROOTS
        tool.SHARE_DIR_ALLOWED_ROOTS = str(allowed)
        self.addCleanup(setattr, tool, "SHARE_DIR_ALLOWED_ROOTS", old_roots)

        self.assertFalse(tool.is_path_allowed(allowed))
        self.assertTrue(tool.is_path_allowed(allowed / "child"))
        self.assertFalse(tool.is_path_allowed(sibling / "child"))

    def test_deepest_allowed_root_is_selected(self) -> None:
        outer = self.test_root / "outer"
        inner = outer / "inner"
        inner.mkdir(parents=True)
        old_roots = tool.SHARE_DIR_ALLOWED_ROOTS
        tool.SHARE_DIR_ALLOWED_ROOTS = f"{outer}:{inner}"
        self.addCleanup(setattr, tool, "SHARE_DIR_ALLOWED_ROOTS", old_roots)

        self.assertEqual(tool.find_allowed_root_for_path(inner / "x"), inner.resolve())


class SubjectResolutionTests(unittest.TestCase):
    @staticmethod
    def completed(returncode: int, stdout: str = "") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess([], returncode, stdout, "")

    def test_explicit_group_only_queries_group_database(self) -> None:
        with mock.patch.object(
            tool, "run_local", return_value=self.completed(0, "research:x:1000:")
        ) as run_local:
            result = tool.resolve_subject("@research")

        self.assertEqual(result, ("group", "research"))
        run_local.assert_called_once_with(["getent", "group", "research"])

    def test_bare_name_prefers_user_over_group(self) -> None:
        with mock.patch.object(
            tool, "run_local", return_value=self.completed(0, "alex:x:1000:1000::/home/alex:/bin/bash")
        ) as run_local:
            result = tool.resolve_subject("alex")

        self.assertEqual(result, ("user", "alex"))
        run_local.assert_called_once_with(["getent", "passwd", "alex"])

    def test_missing_subject_exits_with_clear_message(self) -> None:
        with mock.patch.object(tool, "run_local", return_value=self.completed(2)):
            with self.assertRaisesRegex(SystemExit, "user or group 'missing' does not exist"):
                tool.resolve_subject("missing")


class TargetCollectionTests(HomeDirectoryTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.share = self.test_root / "share"
        self.deep = self.share / "dir" / "deep"
        self.deep.mkdir(parents=True)
        (self.share / "top.txt").write_text("top", encoding="utf-8")
        (self.deep / "nested.txt").write_text("nested", encoding="utf-8")

    def test_non_recursive_collection_stops_after_immediate_children(self) -> None:
        targets, directories = tool.collect_local_targets(self.share, recurse=False)

        self.assertEqual(set(targets), {self.share, self.share / "dir", self.share / "top.txt"})
        self.assertEqual(set(directories), {self.share, self.share / "dir"})
        self.assertNotIn(self.deep, targets)

    def test_recursive_collection_includes_entire_tree(self) -> None:
        targets, directories = tool.collect_local_targets(self.share, recurse=True)

        self.assertIn(self.deep / "nested.txt", targets)
        self.assertIn(self.deep, directories)

    def test_file_has_no_default_acl_target(self) -> None:
        path = self.share / "top.txt"

        targets, directories = tool.collect_local_targets(path, recurse=False)

        self.assertEqual(targets, [path.resolve()])
        self.assertEqual(directories, [])


class CommandConstructionTests(unittest.TestCase):
    def test_readwrite_builds_access_and_default_commands(self) -> None:
        commands = tool.build_setfacl_commands(
            "readwrite",
            "group",
            "research",
            ["/srv/share", "/srv/share/file"],
            ["/srv/share"],
            owner_user="owner",
            recurse=True,
        )

        self.assertEqual(
            commands,
            [
                "setfacl -R -m g:research:rwX /srv/share /srv/share/file",
                "setfacl -R -m d:g:research:rwX,d:u:owner:rwX /srv/share",
            ],
        )

    def test_owner_is_not_duplicated_in_default_acl(self) -> None:
        commands = tool.build_setfacl_commands(
            "read", "user", "owner", ["/srv/share"], ["/srv/share"], owner_user="owner"
        )

        self.assertEqual(commands[-1], "setfacl -m d:u:owner:r-X /srv/share")

    def test_undo_builds_access_and_default_removals(self) -> None:
        commands = tool.build_remove_acl_commands(
            "user", "alex", ["/srv/share"], ["/srv/share"], recurse=False
        )

        self.assertEqual(
            commands,
            [
                "setfacl -x u:alex /srv/share",
                "setfacl -x d:u:alex /srv/share",
            ],
        )

    def test_chunking_keeps_every_item_once(self) -> None:
        items = ["aaaa", "bbbb", "cccc"]

        chunks = tool._chunk_by_argv_limit(items, base_len=5, max_len=10)

        self.assertEqual(chunks, [["aaaa"], ["bbbb"], ["cccc"]])


class ParentAclTests(unittest.TestCase):
    def test_traverse_acl_stays_inside_allowed_remote_root(self) -> None:
        with mock.patch.object(
            tool,
            "run_ssh",
            return_value=subprocess.CompletedProcess([], 0, "", ""),
        ) as run_ssh:
            tool.apply_traverse_x(
                "nfs.example", "/srv/home/alice/share", "/srv/home/alice", "user", "bob", False
            )

        command = run_ssh.call_args.args[1]
        self.assertEqual(
            command,
            "setfacl -m u:bob:--x /srv/home/alice",
        )
        self.assertNotIn(" /srv/home ", f" {command} ")

    def test_unrelated_boundary_does_not_run_ssh(self) -> None:
        with mock.patch.object(tool, "run_ssh") as run_ssh:
            tool.apply_traverse_x(
                "nfs.example", "/srv/home/alice/share", "/different/root", "user", "bob", False
            )

        run_ssh.assert_not_called()


class ShowFormattingTests(unittest.TestCase):
    SAMPLE = """\
# file: /srv/share
# owner: alice
# group: staff
user::rwx
user:bob:r-x
group::r-x
group:research:rw-\t#effective:r--
mask::rwx
other::---
default:user:bob:rwx
"""

    def test_human_output_normalizes_and_sorts_principals(self) -> None:
        rendered = tool.format_show_output(self.SAMPLE)

        self.assertEqual(
            rendered,
            "# file: /srv/share\n"
            "read user:alice,user:bob,group:research,group:staff\n"
            "write user:alice,group:research\n"
            "execute user:alice,user:bob,group:staff\n",
        )

    def test_show_raw_passes_remote_output_through(self) -> None:
        args = types.SimpleNamespace(recurse=False, raw=True)
        result = subprocess.CompletedProcess([], 0, self.SAMPLE, "")

        with mock.patch.object(tool, "run_ssh", return_value=result), mock.patch(
            "sys.stdout", new_callable=lambda: __import__("io").StringIO()
        ) as stdout:
            status = tool.handle_show(args, "nfs.example", "/srv/share")

        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue(), self.SAMPLE)


class CliTests(HomeDirectoryTestCase):
    def test_help_runs_as_a_real_subprocess(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("readwrite", result.stdout)
        self.assertIn("undo", result.stdout)

    def test_flags_work_before_and_after_action(self) -> None:
        parser = tool.build_arg_parser()

        before = parser.parse_args(["-r", "show", "/home/user/share"])
        after = parser.parse_args(["show", "-r", "/home/user/share"])

        self.assertTrue(before.recurse)
        self.assertTrue(after.recurse)

    def test_dry_run_readwrite_writes_audit_but_never_calls_ssh(self) -> None:
        share = self.test_root / "share"
        share.mkdir()
        (share / "file.txt").write_text("data", encoding="utf-8")
        mount = tool.NfsMount(str(self.test_root), "nfs.example", "/srv/test")
        audit = self.test_root / "audit.jsonl"

        old_roots = tool.SHARE_DIR_ALLOWED_ROOTS
        old_log_path = tool.LOG_PATH
        tool.SHARE_DIR_ALLOWED_ROOTS = str(self.test_root)
        tool.LOG_PATH = audit
        self.addCleanup(setattr, tool, "SHARE_DIR_ALLOWED_ROOTS", old_roots)
        self.addCleanup(setattr, tool, "LOG_PATH", old_log_path)

        argv = [str(SCRIPT), "readwrite", "-n", "-r", str(share), "bob"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            tool, "parse_proc_mounts", return_value=[mount]
        ), mock.patch.object(tool, "resolve_subject", return_value=("user", "bob")), mock.patch.object(
            tool, "run_ssh"
        ) as run_ssh, mock.patch.dict(os.environ, {"USER": "owner"}):
            status = tool.main()

        self.assertEqual(status, 0)
        run_ssh.assert_not_called()
        record = json.loads(audit.read_text(encoding="utf-8"))
        self.assertEqual(record["action"], "readwrite")
        self.assertEqual(record["remote_path"], "/srv/test/share")
        self.assertTrue(record["recurse"])
        self.assertTrue(record["dry_run"])

    def test_path_outside_allowed_root_stops_before_mount_detection(self) -> None:
        allowed = self.test_root / "allowed"
        allowed.mkdir()
        outside = self.test_root / "outside"
        outside.mkdir()
        old_roots = tool.SHARE_DIR_ALLOWED_ROOTS
        tool.SHARE_DIR_ALLOWED_ROOTS = str(allowed)
        self.addCleanup(setattr, tool, "SHARE_DIR_ALLOWED_ROOTS", old_roots)

        argv = [str(SCRIPT), "show", str(outside)]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            tool, "parse_proc_mounts"
        ) as parse_mounts:
            status = tool.main()

        self.assertEqual(status, 3)
        parse_mounts.assert_not_called()

    def test_missing_path_stops_before_any_remote_processing(self) -> None:
        missing = self.test_root / "missing"
        old_roots = tool.SHARE_DIR_ALLOWED_ROOTS
        tool.SHARE_DIR_ALLOWED_ROOTS = str(self.test_root)
        self.addCleanup(setattr, tool, "SHARE_DIR_ALLOWED_ROOTS", old_roots)

        argv = [str(SCRIPT), "read", str(missing), "bob"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            tool, "parse_proc_mounts"
        ) as parse_mounts, mock.patch.object(
            tool, "resolve_subject"
        ) as resolve_subject, mock.patch.object(
            tool, "run_ssh"
        ) as run_ssh:
            status = tool.main()

        self.assertEqual(status, 2)
        parse_mounts.assert_not_called()
        resolve_subject.assert_not_called()
        run_ssh.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
