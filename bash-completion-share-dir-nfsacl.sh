# Bash completion for share-dir-nfsfacl
#
# Save as (example):
#   /etc/bash_completion.d/share-dir-nfsfacl
# or (user):
#   ~/.local/share/bash-completion/completions/share-dir-nfsfacl
#
# NOTE:
# - The script binary is expected to be named: share-dir-nfsfacl
# - This completion file name can stay "share-dir-nfsfacl-v3" if you want, but the
#   completion function targets the final command name (no -v3 suffix).

_share_dir_nfsfacl()
{
  local cur prev words cword
  _init_completion -s || return

  local cmd="${words[0]}"
  local action=""

  # Find first non-option word after the command -> action
  local i
  for ((i=1; i < ${#words[@]}; i++)); do
    case "${words[i]}" in
      -*) ;;  # skip global options
      *) action="${words[i]}"; break ;;
    esac
  done

  # Global options
  local global_opts="-h --help -n --dry-run -v --verbose"
  local actions="read readwrite undo show list"

  # If no action yet, complete actions and global opts
  if [[ -z "$action" ]]; then
    COMPREPLY=( $(compgen -W "${actions} ${global_opts}" -- "$cur") )
    return
  fi

  # Per-action options
  local common_path_opts="-h --help"
  local rw_opts="-r --recurse"
  local undo_opts="-r --recurse -p --parent"

  case "$action" in
    read|readwrite)
      # Options
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "${rw_opts} ${global_opts} ${common_path_opts}" -- "$cur") )
        return
      fi

      # Positional completion: PATH then SUBJECT
      # Determine how many positionals already present after action
      local pos=()
      for ((i=1; i < ${#words[@]}; i++)); do
        # ignore options
        [[ "${words[i]}" == -* ]] && continue
        # ignore command and action
        [[ "${words[i]}" == "$cmd" || "${words[i]}" == "$action" ]] && continue
        pos+=("${words[i]}")
      done

      if (( ${#pos[@]} == 0 )); then
        _filedir -d
        return
      fi

      if (( ${#pos[@]} == 1 )); then
        # Suggest users and groups. Groups are suggested with @ prefix.
        # Users from /etc/passwd
        local users groups
        users=$(cut -d: -f1 /etc/passwd 2>/dev/null)
        groups=$(cut -d: -f1 /etc/group 2>/dev/null | sed 's/^/@/')
        COMPREPLY=( $(compgen -W "${users} ${groups}" -- "$cur") )
        return
      fi

      return
      ;;

    undo)
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "${undo_opts} ${global_opts} ${common_path_opts}" -- "$cur") )
        return
      fi

      local pos=()
      for ((i=1; i < ${#words[@]}; i++)); do
        [[ "${words[i]}" == -* ]] && continue
        [[ "${words[i]}" == "$cmd" || "${words[i]}" == "$action" ]] && continue
        pos+=("${words[i]}")
      done

      if (( ${#pos[@]} == 0 )); then
        _filedir -d
        return
      fi

      if (( ${#pos[@]} == 1 )); then
        local users groups
        users=$(cut -d: -f1 /etc/passwd 2>/dev/null)
        groups=$(cut -d: -f1 /etc/group 2>/dev/null | sed 's/^/@/')
        COMPREPLY=( $(compgen -W "${users} ${groups}" -- "$cur") )
        return
      fi

      return
      ;;

    show)
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "${rw_opts} ${global_opts} ${common_path_opts}" -- "$cur") )
        return
      fi
      _filedir -d
      return
      ;;

    list)
      if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "${global_opts} ${common_path_opts}" -- "$cur") )
      fi
      return
      ;;

    *)
      # Unknown action; fall back to actions
      COMPREPLY=( $(compgen -W "${actions}" -- "$cur") )
      return
      ;;
  esac
}

# Register completion for the final command name (no -v3 suffix)
complete -F _share_dir_nfsfacl share-dir-nfsfacl
