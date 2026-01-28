# share-dir manual

`share-dir` manages POSIX ACLs (extended ACLs) to grant read or read/write access
to files and directories, with logging, listing, and undo support.

## Requirements

- Linux filesystem with POSIX ACL support
- Python 3
- `pylibacl` (Python package `posix1e`)

## Usage

```bash
share-dir [-r] [-n] [-v] read|readwrite PATH SUBJECT [SUBJECT...]
share-dir [-n] [-v] show PATH
share-dir [-n] [-v] undo [-p] PATH
share-dir [-n] [-v] list [-H]
```

## Commands

- `read PATH SUBJECT`  
  Grant read access. If PATH is a directory, also grants traverse (`+x`) and
  sets a default ACL so new children inherit permissions. You can pass multiple
  SUBJECTs in one command.
- `readwrite PATH SUBJECT`  
  Grant read/write access. If PATH is a directory, also grants traverse (`+x`)
  and sets a default ACL so new children inherit permissions. You can pass multiple
  SUBJECTs in one command.
- `show PATH`  
  Print the current ACL (and default ACL if a directory) plus the last logged
  operation for that path.
- `list`  
  List all paths seen in the audit log (last `read`/`readwrite` per path).
- `list -H`  
  List without the header row.
- `undo PATH`  
  Restore ACLs from the last `read`/`readwrite` operation on PATH.
- `undo -p PATH`  
  Also remove SUBJECT entries from parent directories used for traverse. This
  can break other shares that rely on those entries.

## Options

- `-r`, `--recurse`  
  Apply changes to all children. Without this, only PATH and its direct children
  are updated for directories.
- `-n`, `--dry-run`  
  Do not change ACLs or logs; only print what would happen (debug output with `-v`).
- `-v`  
  Increase logging verbosity (repeat for more detail).

## SUBJECT format

`SUBJECT` identifies a user or group:

- Explicit: `u:login` or `g:group`
- Autodetect: `login` (tries user, then group)

Examples:

```bash
share-dir read /data/report u:alice
share-dir readwrite /data/project g:analysts
share-dir read /data/public bob
share-dir read /data/public u:alice g:team
```

## Allowed roots (safety)

To avoid granting traverse (`+x`) outside approved locations, `share-dir`
requires PATH to be under allowed roots. Configure with:

```bash
export SHARE_DIR_ALLOWED_ROOTS="/data;/storage;/projects"
```

If not set, the default is:

```bash
export SHARE_DIR_ALLOWED_ROOTS="$HOME;/tmp;/data;/storage;/projects"
```

If PATH is outside these roots, the command exits with an error.

## Logging and undo

- Audit log: `~/.shared_dirs`

Each `read`/`readwrite` writes a log record with the previous ACL state. `undo`
restores ACLs from the last log record for that PATH. `list` reads the log and
shows the last share operation for each path.

## Notes

- Symlink targets are refused for safety.
- For directories, default ACLs are updated so new files inherit the shared
  permissions.

## Examples

```bash
# Share a directory for read access (recursively)
share-dir -r read /projects/demo u:alice

# Share a file for read/write
share-dir readwrite /projects/demo/plan.txt g:team

# Inspect ACLs and last operation
share-dir show /projects/demo

# Undo last share on a path
share-dir undo /projects/demo
```
