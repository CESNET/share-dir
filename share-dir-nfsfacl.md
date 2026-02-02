# share-dir-nfsfacl

User manual for **share-dir-nfsfacl.py** – a command‑line tool for managing extended POSIX ACLs on NFS directories by applying changes **directly on the storage server over SSH**.

---

## Purpose

On front‑end (FE) machines with NFS mounts, standard tools like `ls` do **not reliably show extended ACLs** and `setfacl` may be unavailable or intentionally restricted.

`share-dir-nfsfacl.py` solves this by:

* detecting which **NFS server** backs a given local path
* mapping the local path to the **server‑side filesystem path**
* applying ACL changes **on the storage server** via `getfacl` / `setfacl` over SSH
* keeping a local **audit log** of all changes

The tool is designed to be:

* safe (explicit allowed roots, no shell pipelines)
* compatible with restricted environments (e.g. jailkit)
* predictable and auditable

---

## Supported actions

```
share-dir-nfsfacl.py {read,readwrite,undo,show,list} [PATH] [LOGIN|@GROUP]
```

### `read`

Grant **read‑only** access (`r-X`) to a user or group.

### `readwrite`

Grant **read/write** access (`rwX`) to a user or group.

### `undo`

Remove ACL entries previously added for a user or group.

### `show`

Show the effective ACLs on the storage server using `getfacl`.

### `list`

List previously executed ACL changes recorded in the local log file.

---

## Basic usage examples

### Share a directory for reading

```
share-dir-nfsfacl.py read /home/alice/share bob
```

### Share a directory for read/write access

```
share-dir-nfsfacl.py readwrite /home/alice/share bob
```

### Share with a group

```
share-dir-nfsfacl.py read /home/alice/share @research
```

### Show current ACLs (from storage)

```
share-dir-nfsfacl.py show /home/alice/share
```

---

## Recursive operation

By default, the tool applies ACLs only to the **directory itself and its immediate children**.

Use `-r / --recurse` to ask the storage server to apply ACLs **recursively** using `setfacl -R`:

```
share-dir-nfsfacl.py readwrite -r /home/alice/share bob
```

### Important implementation detail

Recursion is implemented by:

* **always** collecting only a *limited local target set* (PATH + one level)
* adding the `-R` flag to `setfacl` commands on the **storage server**

This means:

* recursion is executed entirely on the storage side
* the tool does **not** enumerate the full directory tree locally
* the number of SSH commands stays low even for very large directory trees

### Default ACL behavior with recursion

When recursion is enabled:

* access ACLs are applied recursively using `setfacl -R -m ...`
* default ACLs are also applied recursively using `setfacl -R -m d:...`

Additionally, the tool automatically adds a default ACL entry for the **current user**
(the user running the tool), ensuring that the space owner retains full access to
newly created files and directories:

```
d:u:<current_user>:rwX
```

This does **not** change file ownership; it only affects inherited permissions.

---

## Undoing changes

### Basic undo

```
share-dir-nfsfacl.py undo /home/alice/share bob
```

This removes:

* access ACL entries (`u:bob` or `g:group`)
* default ACL entries on directories

### Undo including parent directories (**dangerous**)

```
share-dir-nfsfacl.py undo -p /home/alice/share bob
```

⚠️ **WARNING**

Using `-p / --parent` also removes ACL entries on **parent directories** up to the allowed root.

This may:

* break other sharing setups
* remove access required by other projects

Use this option **only if you fully understand the ACL layout**.

---

## Dry‑run mode

Use `-n / --dry-run` to see what would be executed **without changing anything**:

```
share-dir-nfsfacl.py readwrite -n -r /home/alice/share bob
```

Dry‑run shows the exact SSH + `setfacl` commands that would run on the storage server.

---

## Verbose logging

Enable debug logging with:

```
-v / --verbose
```

This prints:

* local helper commands (`getent`, path checks)
* SSH commands sent to the storage server

---

## Allowed roots and safety model

The tool only operates under **explicitly allowed directory roots**.

Configured via environment variable:

```
SHARE_DIR_ALLOWED_ROOTS="$HOME:/storage:/scratch"
```

Rules:

* the target path must be **below** one of these roots
* operating directly on the root itself is forbidden

If a path is outside allowed roots, the tool aborts.

---

## What happens under the hood

### `read` / `readwrite`

1. Determine which NFS mount backs the local path
2. Resolve the corresponding server‑side path
3. Verify the path is under an allowed root
4. Ensure the user/group can **traverse parent directories** (`--x` only)
5. Apply access ACLs using `setfacl` (optionally with `-R`)
6. Apply default ACLs to directories (optionally with `-R`)
7. Automatically add a default ACL entry for the current user (`d:u:<current_user>:rwX`)
8. Log the operation to `~/.shared_dirs`

### `undo`

* Remove access ACL entries for the given user/group
* Remove default ACL entries on directories
* When `-r` is used, removal is done recursively using `setfacl -R`
* With `--parent`, parent directory ACLs are also cleaned up (dangerous)

---

## Audit log

All modifying actions are logged to:

```
~/.shared_dirs
```

Each entry contains:

* timestamp (UTC)
* action (`read`, `readwrite`, `undo`)
* local path
* NFS server and export
* subject (user/group)
* recursion and dry‑run flags

Use:

```
share-dir-nfsfacl.py list
```

to inspect past actions.

---

## Notes and limitations

* ACL changes are applied **on the storage server**, not on the FE
* `ls` output on FE may be misleading (missing `+` for extended ACLs)
* always use `show` to inspect the real ACL state
* recursive operations rely on `setfacl -R` behavior of the storage filesystem
* undo operations are **best‑effort** (missing entries are ignored)

### `setfacl: Operation not permitted`

During `read`, `readwrite`, or `undo` operations you may encounter errors like:

```
setfacl: <PATH>: Operation not permitted
```

This typically happens in the following scenario:

* write access was granted to a directory via ACLs
* a **different user** created files or subdirectories inside that directory
* those newly created objects are **owned by that user**

When the tool later tries to modify ACLs on such objects (especially during
recursive operations), the storage filesystem may deny the change, resulting
in this error.

Important notes:

* this is a **filesystem‑level permission issue**, not a bug in the tool
* ownership of files is determined by the creating user and **cannot be overridden by ACLs**
* the error may appear intermittently, depending on which objects are touched

Recommended mitigations:

* expect this behavior in shared writeable directories
* use `--dry-run` to preview the scope of recursive operations
* prefer group‑based sharing with controlled write access
* avoid unnecessary recursive ACL changes on large, actively used trees

---

## Exit codes

* `0` – success
* `2` – path not on NFS
* `3` – security / configuration error
* `130` – interrupted by user

---

## Recommended usage pattern

* always start with `-n` when unsure
* prefer group‑based sharing (`@group`)
* avoid `--parent` unless absolutely necessary
* use `show` instead of `ls` to inspect ACLs

---

*End of manual.*
