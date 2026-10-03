#!/usr/bin/env bash
# Eén commando op een lege Debian 12/13-container (als root):
#   apt update && apt install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Jonasz1996/homepage/nieuwste/deploy/bootstrap.sh)
# Haalt de code op (of werkt ze bij) in /opt/homepage en voert daarna deploy/install.sh uit.
# Opnieuw uitvoeren = bijwerken naar de nieuwste versie. Andere branch: BRANCH=naam bash <(curl ...)
set -euo pipefail

REPO="${REPO:-https://github.com/Jonasz1996/homepage}"
APP_DIR=/opt/homepage
# Branch "nieuwste" volgt altijd de nieuwste (nog niet gemerge) versie. Bestaat die niet meer,
# dan is alles in main gemerged.
LATEST_BRANCH=nieuwste

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }

printf '\n\033[1;37m==> git installeren\033[0m\n'
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git ca-certificates curl

has_app() { git ls-remote --exit-code "$REPO" "refs/heads/$1" >/dev/null 2>&1 \
  && curl -fsSL -o /dev/null "${REPO/github.com/raw.githubusercontent.com}/$1/deploy/install.sh"; }

if [ -z "${BRANCH:-}" ]; then
  if has_app "$LATEST_BRANCH"; then
    BRANCH=$LATEST_BRANCH
  else
    BRANCH=main
  fi
fi

printf '\n\033[1;37m==> code ophalen (%s, branch %s)\033[0m\n' "$REPO" "$BRANCH"
if [ -d "$APP_DIR/.git" ]; then
  git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
  git -C "$APP_DIR" fetch -q origin "$BRANCH"
  git -C "$APP_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
  git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
elif [ -e "$APP_DIR" ] && [ -n "$(ls -A "$APP_DIR" 2>/dev/null)" ]; then
  echo "$APP_DIR bestaat al maar is geen git-repository. Verplaats of verwijder die map eerst."; exit 1
else
  git clone -q -b "$BRANCH" "$REPO" "$APP_DIR"
fi
git -C "$APP_DIR" log -1 --format='versie: %h %s'

exec bash "$APP_DIR/deploy/install.sh"
