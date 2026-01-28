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

By default, only the directory itself and its **immediate children** are modified.

Use `-r / --recurse` to apply ACLs recursively:

```
share-dir-nfsfacl.py readwrite -r /home/alice/share bob
```

This will:

* apply ACLs to all files and subdirectories
* apply **default ACLs** to all directories so new files inherit permissions

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

For `read` / `readwrite`:

1. Determine which NFS mount backs the local path
2. Resolve the corresponding server‑side path
3. Ensure the user/group can **traverse parent directories** (`--x` only)
4. Apply access ACLs to files and directories
5. Apply default ACLs to directories
6. Log the operation to `~/.shared_dirs`

For `undo`:

* ACL entries for the given user/group are removed
* with `--parent`, parent directory ACLs are also cleaned up

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
* `ls` output on FE may still be misleading (missing `+`)
* use `show` to see the real ACL state
* undo is **best‑effort** (missing entries are ignored)

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
