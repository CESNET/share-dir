# AGENTS.md

## Project Overview

This repository contains two primary ACL-sharing CLI tools:

- `share-dir.py`
  Manages POSIX ACLs locally using Python `posix1e` / `pylibacl`.
- `share-dir-nfsfacl.py`
  Manages POSIX ACLs for NFS-backed paths by translating local paths to storage-server paths and running `getfacl` / `setfacl` remotely over SSH.

Each primary tool has matching user documentation:

- `share-dir.md`
- `share-dir-nfsfacl.md`

Keep code and documentation aligned when changing CLI behavior, flags, subject formats, recursion semantics, logging, or safety constraints.

## Files That Matter

- `share-dir.py`: local ACL implementation
- `share-dir.md`: manual for `share-dir.py`
- `share-dir-nfsfacl.py`: NFS/SSH ACL implementation
- `share-dir-nfsfacl.md`: manual for `share-dir-nfsfacl.py`
- `share-dir-remote.py`: older wrapper that forwards `share-dir` to an NFS server via SSH
- `bash-completion-share-dir-nfsacl.sh`: shell completion for the NFS tool

## Tool Split

Use `share-dir.py` when the target filesystem supports local POSIX ACL operations and `pylibacl` is available.

Use `share-dir-nfsfacl.py` when the user is operating from a front-end machine on NFS mounts where direct ACL inspection or mutation is unreliable, restricted, or unavailable.

## Behavioral Constraints

- Both tools are safety-sensitive because they change filesystem access.
- Both rely on allowed-root restrictions via `SHARE_DIR_ALLOWED_ROOTS`.
- Recursive operations and parent traversal handling are important behavior, not incidental implementation details.
- `undo` behavior must stay conservative and documented clearly, especially any parent ACL removal mode.
- Audit logging to `~/.shared_dirs` is part of the product behavior.

## Change Rules

- If you change CLI syntax or semantics, update the matching `.md` file in the same task.
- If you change `share-dir-nfsfacl.py` options or action names, also review `bash-completion-share-dir-nfsacl.sh`.
- Preserve dry-run behavior.
- Preserve or improve path-safety checks; do not relax them casually.
- Avoid introducing features that require network access during tests unless explicitly requested.

## Verification Guidance

There is no visible automated test suite in this repository. Prefer lightweight verification:

- `python3 share-dir.py --help`
- `python3 share-dir-nfsfacl.py --help`
- `python3 share-dir-remote.py --help`

For logic changes, also sanity-check the relevant docs and option parsing paths. Do not run live ACL-changing commands against real paths unless the user explicitly asks for that validation.

## Notes For Future Agents

- Favor minimal, targeted changes.
- Read the matching manual before editing a tool with nontrivial behavior changes.
- Treat `share-dir.py` and `share-dir-nfsfacl.py` as the main maintained entrypoints unless the user asks to revive or expand `share-dir-remote.py`.
