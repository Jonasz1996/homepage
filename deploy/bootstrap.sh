#!/usr/bin/env bash
# Eén commando op een lege Debian 12/13-container (als root):
#   apt update && apt install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Jonasz1996/homepage/nieuwste/deploy/bootstrap.sh)
# Haalt de code op (of werkt ze bij) in /opt/homepage en voert daarna deploy/install.sh uit.
# Opnieuw uitvoeren = bijwerken.
#
# Welke versie:
#   stabiel   de laatste release (vX.Y.Z). Aanbevolen.
#   nieuwste  wat net gebouwd is, om te testen (branch "nieuwste", of main als die er niet meer is).
# De eerste keer wordt het gevraagd en daarna onthouden in /etc/homepage/kanaal. Zelf kiezen of wisselen:
#   KANAAL=stabiel bash <(curl ...)      of      KANAAL=nieuwste bash <(curl ...)
# Een andere branch: BRANCH=naam bash <(curl ...). Een vorige versie terugzetten: homepage-terugzetten.
set -euo pipefail

REPO="${REPO:-https://github.com/Jonasz1996/homepage}"
APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
LATEST_BRANCH=nieuwste

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }

printf '\n\033[1;37m==> git installeren\033[0m\n'
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q git ca-certificates curl

has_app() { git ls-remote --exit-code "$REPO" "refs/heads/$1" >/dev/null 2>&1 \
  && { [[ $REPO != *github.com* ]] || curl -fsSL -o /dev/null "${REPO/github.com/raw.githubusercontent.com}/$1/deploy/install.sh"; }; }
# Laatste release: de hoogste tag vX.Y.Z (geen voorlopige versies zoals v1.1.0-rc1).
latest_release() { git ls-remote --tags --refs "$REPO" 'v*' 2>/dev/null | sed 's#.*refs/tags/##' \
  | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1; }

RELEASE=$(latest_release || true)
# Een eerder gekozen branch (BRANCH=...) blijft bij een update gekozen.
[ -n "${BRANCH:-}" ] || BRANCH=$(cat "$CONF_DIR/branch" 2>/dev/null || true)
KANAAL="${KANAAL:-$(cat "$CONF_DIR/kanaal" 2>/dev/null || true)}"
if [ -n "${BRANCH:-}" ]; then
  KANAAL=branch
elif [ -z "$KANAAL" ] && [ -n "$RELEASE" ]; then
  if [ -t 0 ]; then
    printf '\nWelke versie wil je?\n  1) stabiel   %s (aanbevolen)\n  2) nieuwste  om nieuwe functies te testen\n' "$RELEASE"
    read -r -p "Keuze [1]: " k || k=""
    case "${k:-1}" in 2|nieuwste) KANAAL=nieuwste ;; *) KANAAL=stabiel ;; esac
  else
    KANAAL=stabiel
  fi
fi
case "$KANAAL" in
  stabiel)
    [ -n "$RELEASE" ] || { echo "Er is nog geen release. Kies KANAAL=nieuwste."; exit 1; }
    REF=$RELEASE ;;
  branch) REF=$BRANCH ;;
  *)
    # nieuwste, of nog geen keuze en nog geen release (zoals vroeger)
    if has_app "$LATEST_BRANCH"; then REF=$LATEST_BRANCH; else REF=main; fi ;;
esac

# Welke versie draaide er tot nu toe: om naar terug te kunnen (homepage-terugzetten).
PREV=$(git -C "$APP_DIR" rev-parse -q --verify HEAD 2>/dev/null || true)

printf '\n\033[1;37m==> code ophalen (%s, %s)\033[0m\n' "$REPO" "$REF"
if [ -d "$APP_DIR/.git" ]; then
  git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
  if [ "$KANAAL" = stabiel ]; then
    git -C "$APP_DIR" fetch -q origin "refs/tags/$REF:refs/tags/$REF"
    git -C "$APP_DIR" checkout -q -f --detach "refs/tags/$REF"
  else
    git -C "$APP_DIR" fetch -q origin "$REF"
    git -C "$APP_DIR" checkout -q -f -B "$REF" "origin/$REF"
    git -C "$APP_DIR" reset -q --hard "origin/$REF"
  fi
elif [ -e "$APP_DIR" ] && [ -n "$(ls -A "$APP_DIR" 2>/dev/null)" ]; then
  echo "$APP_DIR bestaat al maar is geen git-repository. Verplaats of verwijder die map eerst."; exit 1
else
  git -c advice.detachedHead=false clone -q -b "$REF" "$REPO" "$APP_DIR"
fi
git -C "$APP_DIR" log -1 --format='versie: %h %s'

install -d "$CONF_DIR"
if [ "$KANAAL" = branch ]; then
  echo "$BRANCH" > "$CONF_DIR/branch"
else
  rm -f "$CONF_DIR/branch"
  # Alleen een echte keuze onthouden: zonder release blijft het zoals vroeger, en wordt de keuze later gevraagd.
  if [ "$KANAAL" = stabiel ] || [ "$KANAAL" = nieuwste ]; then echo "$KANAAL" > "$CONF_DIR/kanaal"; fi
fi

export HOMEPAGE_KANAAL="${KANAAL:-nieuwste}" HOMEPAGE_PREV_COMMIT="$PREV"
exec bash "$APP_DIR/deploy/install.sh"
