#!/usr/bin/env bash
# Kit post-acquire hook: Swift
# Runs once after the workarea is acquired and ready.
# Resolves SPM package dependencies (NOT the base toolchain).
#
# PATH note: swiftly (like rustup) installs the Swift toolchain and writes an
# env file rather than a system-wide install. Until demand.env threads that
# onto PATH for every kit command, this hook sources swiftly's env itself so
# `swift` resolves for the next command.

set -euo pipefail

WORKAREA_ROOT="${1:-$(pwd)}"
cd "$WORKAREA_ROOT"

# Make swift visible even if the composed env hasn't augmented PATH yet.
# swiftly's env file lives at one of two paths depending on OS/install mode.
if [ -f "$HOME/.local/share/swiftly/env.sh" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.local/share/swiftly/env.sh"
elif [ -f "$HOME/.swiftly/env.sh" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.swiftly/env.sh"
fi

echo "[swift kit] post_acquire: resolving SPM dependencies..."

if command -v swift &>/dev/null && [ -f Package.swift ]; then
  swift package resolve
else
  echo "[swift kit] WARNING: swift toolchain or Package.swift not found. Skipping resolve."
fi

echo "[swift kit] post_acquire: done."
