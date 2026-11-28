#!/usr/bin/env bash
# Pull a container image, trying every registry that carries it before giving up.
#
# Why this exists
# ---------------
# A hosted runner pulls anonymously against a quota it shares with everyone
# else on the same egress, and both public registries answer transient denials
# while the image is perfectly present: ECR Public has returned "Data limit
# exceeded" and "Rate exceeded", Docker Hub a rate-limit shaped "repository
# does not exist", quay a 401 on a manifest HEAD. A step that pulls once and
# gives up turns whichever registry blinked into a single point of failure for
# the whole build.
#
# This is the retry-and-fallback loop that `.github/actions/start-postgres`
# used to carry inline. It lives here so there is exactly one implementation:
# that action calls it, and so does every workflow step that starts a
# container of its own.
#
# Usage
# -----
#     image="$("$GITHUB_WORKSPACE/scripts/ci/pull_image.sh" <reference> [<mirror> ...])"
#     docker run ... "$image"
#
# References are tried in rotation, three rounds, 60 seconds per attempt, with
# a 5, 10, 15 second backoff between rounds. `PULL_IMAGE_ATTEMPT_SECONDS` and
# `PULL_IMAGE_BACKOFF_SECONDS` override those two numbers; they exist so
# tests/test_pull_image_helper.py can exercise all three rounds in under a
# second rather than asserting the loop by reading it. The winning reference
# is the only thing written to stdout, so the caller can capture it; progress
# and warnings go to stderr. Pass a single reference for an image only one
# registry carries — the retries still apply, there is just nowhere to fall
# back to.
#
# A missing image still fails, loudly: after every reference has been tried in
# every round this exits non-zero naming all of them. Surviving a transient
# limit is the point; papering over a bad reference is not.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "::error::pull_image.sh needs at least one image reference" >&2
  exit 2
fi

candidates=("$@")
count="${#candidates[@]}"

# Spread first attempts across the mirrors rather than sending every
# concurrent job to the same anonymous quota. Each round still tries them
# all, so any one registry may be unavailable without taking out CI.
offset=$(( ${GITHUB_RUN_ID:-0} % count ))
if [ "$offset" -ne 0 ]; then
  candidates=( "${candidates[@]:offset}" "${candidates[@]:0:offset}" )
fi

if [ "$count" -gt 1 ]; then
  retry_hint="trying the next registry"
else
  retry_hint="retrying"
fi

# `timeout` is coreutils. It is always present on the hosted runners this
# runs on; the fallback is so a contributor on macOS without it still gets
# the retries and the fallback, rather than a command-not-found.
timeout_cmd=""
if command -v timeout >/dev/null 2>&1; then
  timeout_cmd="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_cmd="gtimeout"
fi

pull_once() {
  # A registry that accepts the connection but stops responding must not
  # prevent the alternate registry from being attempted.
  if [ -n "$timeout_cmd" ]; then
    "$timeout_cmd" --kill-after=10s "${PULL_IMAGE_ATTEMPT_SECONDS:-60}s" docker pull "$1" >&2
  else
    docker pull "$1" >&2
  fi
}

image=""
for round in 1 2 3; do
  for candidate in "${candidates[@]}"; do
    echo "Pulling $candidate (round $round/3; ${PULL_IMAGE_ATTEMPT_SECONDS:-60}-second limit)" >&2
    if pull_once "$candidate"; then
      image="$candidate"
      break 2
    fi
    echo "::warning::Could not pull $candidate; $retry_hint" >&2
  done
  sleep $(( round * ${PULL_IMAGE_BACKOFF_SECONDS:-5} ))
done

if [ -z "$image" ]; then
  echo "::error::Could not pull ${candidates[0]} from any registry that carries it (tried ${candidates[*]})" >&2
  exit 1
fi

echo "$image"
