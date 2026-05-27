#!/bin/bash
# Login GitHub sekali — setelah itu git push bisa tanpa password.
set -e
export PATH="$HOME/.local/bin:$PATH"

if ! command -v gh >/dev/null 2>&1; then
  echo "Menginstall GitHub CLI..."
  mkdir -p "$HOME/.local/bin"
  ARCH=$(uname -m)
  if [ "$ARCH" = "arm64" ]; then
    ZIP="gh_2.74.2_macOS_arm64.zip"
  else
    ZIP="gh_2.74.2_macOS_amd64.zip"
  fi
  cd /tmp
  curl -fsSL "https://github.com/cli/cli/releases/download/v2.74.2/$ZIP" -o gh.zip
  unzip -qo gh.zip
  cp "gh_2.74.2_macOS_${ARCH/arm64/arm64}/bin/gh" "$HOME/.local/bin/gh" 2>/dev/null || \
    cp gh_*/bin/gh "$HOME/.local/bin/gh"
fi

echo "Buka browser, login GitHub, lalu authorize."
gh auth login -h github.com -p https -w --skip-ssh-key

echo ""
gh auth status
echo ""
echo "Push ke GitHub:"
cd "$(dirname "$0")"
git push origin main
