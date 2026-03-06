# share-dir-nfsfacl

User manual for **share-dir-nfsfacl.py** - a command-line tool for managing extended POSIX ACLs on NFS paths by applying changes directly on the storage server over SSH.

---

## Purpose

On front-end (FE) machines with NFS mounts, standard tools like `ls` may not reliably show extended ACLs, and `setfacl` may be unavailable or restricted.

`share-dir-nfsfacl.py` solves this by:

* detecting which NFS server backs a local path
* mapping local path to server-side filesystem path
* applying ACL changes on the storage server via `getfacl` / `setfacl` over SSH
* writing a local audit log for modifying operations

---

## CLI synopsis

```text
share-dir-nfsfacl.py [-v] [-n] [-r] ACTION ...

ACTION forms:
  read      PATH LOGIN|GROUP|@GROUP
  readwrite PATH LOGIN|GROUP|@GROUP
  undo      [-p|--parent] PATH LOGIN|GROUP|@GROUP
  show      [--raw] PATH
  list
```

Common flags `-v`, `-n`, `-r` are accepted both before and after `ACTION`.

---

## Actions

### `read`

Grant read access (`r-X`) to a user or group.

### `readwrite`

Grant read/write access (`rwX`) to a user or group.

### `undo`

Remove ACL entries for a user or group.

### `show`

Show ACLs from storage using `getfacl -p`.

By default, output is reformatted per file into:

* `read user:...,group:...`
* `write user:...,group:...`
* `execute user:...,group:...`

Use `--raw` to print original `getfacl` output unchanged.

### `list`

Print the local audit log from `~/.shared_dirs`.

---

## Basic usage examples

### Share a directory for reading

```bash
share-dir-nfsfacl.py read /home/alice/share bob
```

### Share a directory for read/write access

```bash
share-dir-nfsfacl.py readwrite /home/alice/share bob
```

### Share with a group

```bash
share-dir-nfsfacl.py read /home/alice/share @research
```

### Show current ACLs (formatted)

```bash
share-dir-nfsfacl.py show /home/alice/share
```

### Show raw `getfacl` output

```bash
share-dir-nfsfacl.py show --raw /home/alice/share
```

### List logged changes

```bash
share-dir-nfsfacl.py list
```

---

## Recursion model

By default, local target expansion is limited to the specified path and (for directories) immediate children.

Use `-r / --recurse` to run recursive operations on storage:

* `read` / `readwrite`: `setfacl -R -m ...`
* `undo`: `setfacl -R -x ...`
* `show`: `getfacl -R -p ...`

Important detail:

* local enumeration stays limited to PATH + one level
* deep traversal is delegated to remote `-R`
* this keeps SSH command count low even for large trees

---

## Default ACL behavior

For directory targets, the tool also sets default ACLs (`d:...`) so new children inherit access.

When sharing to another subject, it also adds a default ACL entry for the current user:

```text
d:u:<current_user>:rwX
```

Current user resolution order:

* `SUDO_USER`
* `USER`
* `getpass.getuser()` fallback

This does not change file ownership.

---

## Undo behavior

### Basic undo

```bash
share-dir-nfsfacl.py undo /home/alice/share bob
```

This removes:

* access ACL entries (`u:<name>` / `g:<name>`)
* default ACL entries on directories (`d:u:<name>` / `d:g:<name>`)

### Undo including parent directories (dangerous)

```bash
share-dir-nfsfacl.py undo -p /home/alice/share bob
```

Warning: `-p / --parent` removes the full ACL entry for that subject on parent directories up to the matched allowed root. This can break other sharing setups.

Undo is best-effort: failures in undo commands are logged as warnings and processing continues.

---

## Dry-run mode

Use `-n / --dry-run` with `read`, `readwrite`, or `undo` to preview remote `setfacl` commands without modifying ACLs.

```bash
share-dir-nfsfacl.py readwrite -n -r /home/alice/share bob
```

---

## Verbose logging

Enable debug logging with `-v / --verbose`.

This includes helper command and SSH command details.

---

## Allowed roots and safety model

The tool only operates under explicitly allowed roots configured by:

```bash
SHARE_DIR_ALLOWED_ROOTS="$HOME:/storage:/scratch"
```

Rules:

* target path must be under one of these roots
* operating directly on the root itself is forbidden

If a path is outside allowed roots, the tool exits with code `3`.

---

## What happens under the hood

### `read` / `readwrite`

1. Resolve local path and validate allowed root.
2. Detect NFS mount and map local path to remote path.
3. Resolve subject type (`user` or `group`; `@name` forces group).
4. Ensure parent directory traversal via `setfacl -m <u|g>:<subject>:--x` up to allowed root boundary.
5. Build local target sets (PATH + immediate children).
6. Build and run remote `setfacl` commands (optionally with `-R`), chunking long target lists.
7. Log operation to `~/.shared_dirs`.

### `undo`

1. Resolve subject and targets.
2. Run remote remove commands for access ACL and default ACL (optionally `-R`).
3. If `--parent` is set, remove subject entry from parent directories up to allowed root.
4. Log operation.

### `show`

1. Map local path to remote path.
2. Run `getfacl -p` (and `-R` when requested).
3. Print formatted view (default) or raw output (`--raw`).

### `list`

Print JSONL log entries from `~/.shared_dirs` as readable one-line records.

---

## Audit log

Modifying actions (`read`, `readwrite`, `undo`) append JSON lines to:

```text
~/.shared_dirs
```

Typical fields include timestamp, action, local path, NFS server/export, remote path, subject, permissions (for grants), recursion flag, and dry-run flag.

---

## Notes and limitations

* ACL changes are applied on storage, not on FE.
* `ls` on FE may not reflect extended ACL state reliably.
* use `show` to inspect ACL state; use `show --raw` for exact `getfacl` output
* recursive behavior depends on storage filesystem `setfacl/getfacl` behavior
* undo operations are best-effort

### `setfacl: Operation not permitted`

You may see errors like:

```text
setfacl: <PATH>: Operation not permitted
```

Common cause:

* write ACL allows another user to create files/directories
* those objects are owned by that other user
* later ACL modification on those objects is denied by the filesystem

This is a filesystem-level permission issue, not ownership override by ACL.

---

## Exit codes

* `0` - success
* `2` - path not on NFS
* `3` - security/configuration error
* `130` - interrupted by user

---

## Recommended usage pattern

* start with `-n` when unsure
* prefer group sharing (`@group`) for teams
* avoid `--parent` unless needed
* use `show` (or `show --raw`) instead of `ls` for ACL verification

---

*End of manual.*
