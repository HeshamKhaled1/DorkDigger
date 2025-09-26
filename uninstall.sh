#!/usr/bin/env bash
set -euo pipefail
target="/usr/local/bin/DorkDigger"

if [ ! -e "$target" ]; then
  echo "$target does not exist. Nothing to do."
  exit 0
fi

if [ -L "$target" ]; then
  echo "Removing symlink $target"
  sudo rm -f "$target"
  echo "Done."
else
  echo "$target exists but is not a symlink. Leaving it in place (not removed)."
fi
