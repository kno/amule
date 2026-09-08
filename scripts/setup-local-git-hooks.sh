#!/bin/sh
# Run this once per clone (from the main or any linked worktree) to enable hooks.

repository=$(git rev-parse --show-toplevel 2>/dev/null) || {
	echo "setup-local-git-hooks: not inside a Git worktree" >&2
	exit 1
}
common_directory=$(git rev-parse --git-common-dir 2>/dev/null) || {
	echo "setup-local-git-hooks: cannot find the common Git directory" >&2
	exit 1
}
common_directory=$(cd "$common_directory" 2>/dev/null && pwd -P) || {
	echo "setup-local-git-hooks: cannot canonicalize the common Git directory" >&2
	exit 1
}

source_hook=$repository/.githooks/post-checkout
hook_directory=$common_directory/amule-hooks
installed_hook=$hook_directory/post-checkout

if [ ! -f "$source_hook" ]; then
	echo "setup-local-git-hooks: missing source hook: $source_hook" >&2
	exit 1
fi

if ! mkdir -p "$hook_directory" || ! cp "$source_hook" "$installed_hook" || ! chmod +x "$installed_hook"; then
	echo "setup-local-git-hooks: could not install post-checkout hook" >&2
	exit 1
fi

if ! git config --local core.hooksPath "$hook_directory"; then
	echo "setup-local-git-hooks: could not configure core.hooksPath" >&2
	exit 1
fi

echo "setup-local-git-hooks: installed post-checkout hook in $hook_directory"
