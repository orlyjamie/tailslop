#!/usr/bin/env bash
# tailworm-triage.sh  —  "The Wolf" edition.
# Walks all 11 Tailworm (tailworm.com) findings and paints each one:
#   GREEN = the door is shut on this box (precondition not enabled)
#   RED   = you left it open (feature is actually on -> this finding is in play)
#   CHECK = can't be judged from the node alone (your call / console job)
#
# READ-ONLY. It runs `tailscale ... status/prefs/serve/lock` (all read verbs),
# reads a couple of config files, and prints. It changes NOTHING.
#
#   Linux:  sudo bash tailworm-triage.sh      (sudo = can read the daemon env)
#   macOS:  bash tailworm-triage.sh

set -u

if [ -t 1 ]; then
  G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; X=$'\e[0m'
else
  G=""; R=""; Y=""; B=""; D=""; X=""
fi

EXPOSED=0
green() { printf '%s GREEN %s %s\n' "$G" "$X" "$*"; }
red()   { printf '%s RED   %s %s\n' "$R" "$X" "$*"; EXPOSED=$((EXPOSED+1)); }
amber() { printf '%s CHECK %s %s\n' "$Y" "$X" "$*"; }
sub()   { printf '%s         %s%s\n' "$D" "$*" "$X"; }
have()  { command -v "$1" >/dev/null 2>&1; }

jget() {
  local json="$1" path="$2"
  if have jq; then
    printf '%s' "$json" | jq -r ".${path} | if . == null then empty else . end" 2>/dev/null
  elif have python3; then
    printf '%s' "$json" | python3 -I -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d,dict) else None
if d is None: sys.exit(0)
print(str(d).lower() if isinstance(d,bool) else d)
' "$path"
  else
    echo "__NOPARSER__"
  fi
}

pref_bool() { # dotted key -> true/false
  local v; v=$(jget "$PREFS" "$1")
  if [ "$v" = "__NOPARSER__" ]; then
    case "$1" in
      RunSSH) printf '%s' "$PREFS" | grep -Eq '"RunSSH":[[:space:]]*true' && echo true || echo false ;;
      AppConnector.Advertise) printf '%s' "$PREFS" | grep -A3 '"AppConnector"' | grep -Eq '"Advertise":[[:space:]]*true' && echo true || echo false ;;
      *) echo false ;;
    esac
  else
    [ "$v" = "true" ] && echo true || echo false
  fi
}

ctrl_url() {
  local v; v=$(jget "$PREFS" ControlURL)
  if [ "$v" = "__NOPARSER__" ]; then
    printf '%s' "$PREFS" | grep -Eo '"ControlURL":[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/'
  else
    printf '%s' "$v"
  fi
}

printf '%s== Tailworm triage ==%s  (read-only; changes nothing)\n\n' "$B" "$X"

TS=""
have tailscale && TS="tailscale"
[ -z "$TS" ] && [ -x "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ] && TS="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
if [ -z "$TS" ]; then
  echo "No tailscale CLI on this machine — nothing for me to triage."
  exit 0
fi

VER=$("$TS" version 2>/dev/null | head -n1)
sub "tailscale ${VER:-?}  (Tailworm tested 1.104.2)"
echo

PREFS=$("$TS" debug prefs 2>/dev/null || true)
SERVE=$("$TS" serve status --json 2>/dev/null || true)

if [ -z "$PREFS" ]; then
  amber "Couldn't read prefs (daemon down, or run with sudo). Re-run before trusting the greens."
  echo
fi

# ---- Findings 1-3 (+5 OOM, + the worm): Tailscale SSH --------------------
SSH=$(pref_bool RunSSH)
if [ "$SSH" = "true" ]; then
  red   "F1-3  Tailscale SSH is ON -> socket-forward-to-root surface (also F5 daemon OOM, and the worm's entry point)."
  amber "      Console job: if any SSH rule is broad-source -> broad-dest, THAT is what makes it spreadable. Narrow to per-pair grants."
else
  green "F1-3  Tailscale SSH OFF -> socket-forward-to-root (1-3), daemon OOM (5), and the worm have no entry point here."
fi

# ---- Finding 4: app connectors (conn25) ----------------------------------
APPC=$(pref_bool AppConnector.Advertise)
if [ "$APPC" = "true" ]; then
  red "F4    This node advertises as an app connector -> unvalidated-destination surface (cloud metadata / LAN / cluster)."
else
  green "F4    Not an app connector."
fi

# ---- Finding 6: headscale (self-hosted control) --------------------------
CURL=$(ctrl_url)
case "$CURL" in
  ""|*controlplane.tailscale.com*|*login.tailscale.com*)
    green "F6    Hosted control plane -> headscale unauth-DoS / onboarding-lockout doesn't apply." ;;
  *)
    amber "F6    Custom control server ($CURL) -> likely headscale: the self-hosted DoS class is in play."
    sub   "Firewall it to admin/VPN only, set a systemd MemoryMax, rate-limit registration." ;;
esac

# ---- Findings 7-11: serve / funnel ---------------------------------------
SERVE_TRIM=$(printf '%s' "$SERVE" | tr -d '[:space:]')
SERVE_ACTIVE=0
case "$SERVE_TRIM" in ""|"{}"|"null") SERVE_ACTIVE=0 ;; *) SERVE_ACTIVE=1 ;; esac

if [ "$SERVE_ACTIVE" = 1 ] && printf '%s' "$SERVE" | grep -q 'tailscaled\.sock'; then
  red "F7    serve forwards to the tailscaled API socket -> remote peers could drive the admin API. Remove it now."
else
  green "F7    No serve forward to the tailscaled API socket."
fi

if [ "$SERVE_ACTIVE" = 1 ] && printf '%s' "$SERVE" | grep -q 'unix:' && ! printf '%s' "$SERVE" | grep -q 'tailscaled\.sock'; then
  amber "F8    serve forwards to a unix socket -> confirm no one else can write to that socket's directory."
else
  green "F8    No serve forward to a unix socket."
fi

if [ "$SERVE_ACTIVE" = 1 ] && printf '%s' "$SERVE" | grep -q 'AllowFunnel'; then
  red "F9    Funnel is ON -> something here faces the public internet."
else
  green "F9    Funnel off."
fi

# F10: TS_SERVE_ALLOW_ALL_INTERFACES
ENVHIT=0
PID=""
have pgrep && PID=$(pgrep -x tailscaled 2>/dev/null | head -n1)
if [ -n "${PID:-}" ] && [ -r "/proc/$PID/environ" ]; then
  tr '\0' '\n' < "/proc/$PID/environ" | grep -q '^TS_SERVE_ALLOW_ALL_INTERFACES=' && ENVHIT=1
fi
have systemctl && systemctl show tailscaled -p Environment 2>/dev/null | grep -q 'TS_SERVE_ALLOW_ALL_INTERFACES' && ENVHIT=1
for f in /etc/default/tailscaled /etc/sysconfig/tailscaled; do
  [ -r "$f" ] && grep -q '^[^#]*TS_SERVE_ALLOW_ALL_INTERFACES' "$f" && ENVHIT=1
done
if [ "$ENVHIT" = 1 ]; then
  red "F10   TS_SERVE_ALLOW_ALL_INTERFACES is set -> serve reachable off-tunnel, ACLs skipped."
else
  green "F10   TS_SERVE_ALLOW_ALL_INTERFACES not set."
fi

if [ "$SERVE_ACTIVE" = 1 ]; then
  amber "F11   serve is active -> the HTTP/2 per-mount auth race only bites if you use per-mount auth (rare, tiny hit-rate)."
else
  green "F11   No serve mounts -> per-mount auth race is N/A."
fi

# ---- verdict -------------------------------------------------------------
echo
if [ "$EXPOSED" -eq 0 ]; then
  printf '%s%s VERDICT: all clear. %sVanilla config — none of Tailworm'\''s preconditions exist on this box.\n' "$G" "$B" "$X"
  printf '%s         Go home. Pretty please.%s\n' "$D" "$X"
else
  printf '%s%s VERDICT: %d RED finding(s) in play. %sNot a worm — a to-do list. Fix the red lines above.\n' "$R" "$B" "$EXPOSED" "$X"
fi
echo
sub "Footnote: the DERP memory-bomb (part of F5/F6) only applies if you've pointed this client at a custom/hostile relay;"
sub "default installs use Tailscale's own relays. And ACLs / auth keys / key-expiry live in the console, not on the node."
