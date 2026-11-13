#!/usr/bin/env bash
# Clone each honeypot at the exact commit the study uses.
#
# Sources land in targets/<name>/src and are ignored by git: this repo pins the
# commits, it does not vendor the code. Re-running is safe and will reset an
# existing checkout to the pinned commit.
set -euo pipefail

cd "$(dirname "$0")"

clone_at() {
  # Separate statements on purpose: every argument to `local` is expanded
  # before any of its assignments take effect, so building dest from name on
  # the same line reads an unset variable.
  local name="$1"
  local url="$2"
  local commit="$3"
  local dest="$name/src"
  if [ -d "$dest/.git" ]; then
    echo "== $name: updating to $commit"
    git -C "$dest" fetch --quiet origin "$commit" 2>/dev/null || git -C "$dest" fetch --quiet origin
  else
    echo "== $name: cloning $url"
    rm -rf "$dest"
    git clone --quiet "$url" "$dest"
  fi
  git -C "$dest" checkout --quiet --detach "$commit"
  echo "   $name at $(git -C "$dest" rev-parse HEAD)"
}

clone_at cowrie     https://github.com/cowrie/cowrie.git          a4237125e8a55493b342dea9e4ede052f9314193
clone_at beelzebub  https://github.com/mariocandela/beelzebub.git df6de36a087c867f7cce90a0d125351bd47b3343
clone_at deceive    https://github.com/splunk/DECEIVE.git         cce98f3dcd9de74f32f683998e95aa19b795724e

echo
echo "Done. Commits above are the ones honeytell.toml records."
