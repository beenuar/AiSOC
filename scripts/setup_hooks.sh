#!/bin/sh
# Point this clone's git hooks at the tracked .githooks/ directory.
#
# Git hooks live in .git/hooks/, which is not version-controlled and therefore
# not shared with anyone who clones the repository. `core.hooksPath` redirects
# git to a tracked directory instead, so the hooks arrive with the checkout and
# every contributor gets the same ones.
#
# This runs automatically as the `prepare` script on `pnpm install`. Run it by
# hand if you do not use pnpm:
#
#     sh scripts/setup_hooks.sh
#
# It is idempotent and safe to run repeatedly.
#
# POSIX sh on purpose, invoked as `sh` and not `bash`. The web image builds on
# Alpine, which ships busybox ash and no bash at all; a `prepare` script that
# assumes bash fails `pnpm install` and takes the whole image build down with
# it. For the same reason package.json runs this as `… || exit 0`: installing
# a git hook is a convenience, and it must never be the reason a build fails.
# CI is what actually enforces the rule.

set -eu

# No git binary at all (slim build image) — nothing to configure.
if ! command -v git >/dev/null 2>&1; then
    echo "setup_hooks: no git binary, nothing to do."
    exit 0
fi

# Not a git checkout (release tarball, Docker build context, vendored copy) —
# there is nothing to configure and that is not an error.
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "setup_hooks: not a git checkout, nothing to do."
    exit 0
fi

ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

if [ ! -d .githooks ]; then
    echo "setup_hooks: .githooks/ not found in $ROOT — nothing to configure." >&2
    exit 0
fi

current=$(git config --get core.hooksPath || true)

if [ -n "$current" ] && [ "$current" != ".githooks" ]; then
    # Someone (or another tool, e.g. husky) already owns hooks here. Say so
    # rather than silently stealing the setting.
    echo "setup_hooks: core.hooksPath is already set to '$current', leaving it alone." >&2
    echo "setup_hooks: to use the repository's hooks run: git config core.hooksPath .githooks" >&2
    exit 0
fi

git config core.hooksPath .githooks

# The executable bit is tracked in git, but a checkout with a restrictive umask
# or a filesystem that drops the mode bit (some Windows/WSL setups) needs help.
chmod +x .githooks/* 2>/dev/null || true

echo "setup_hooks: core.hooksPath -> .githooks"
