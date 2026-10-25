# tailslop

A read-only triage for the **"Tailworm"** report ([tailworm.com](https://tailworm.com)) against Tailscale 1.104.2 / headscale 0.29.5.

The report lists 11 findings. Every one of them is gated behind a feature you have to switch on first. A default `tailscale up` install has **none** of the preconditions. This repo hands you a script that proves it on your own box: green where you're clear, red where you actually turned something on.

It's called `tailslop` because a scary-sounding disclosure with no CVE, no vendor acknowledgement, and no path to compromising a default install is not a reason to reimage the fleet at 2am. Breathe first, triage second.

## The script

**`tailworm-triage.sh`** — read-only. It runs `tailscale debug prefs / status / serve status / lock status`, reads a couple of config files, and prints a GREEN/RED verdict for each finding. It changes nothing.

## Run it

Read it first — it's short and read-only — then run:

```sh
curl -fsSLO https://raw.githubusercontent.com/orlyjamie/tailslop/main/tailworm-triage.sh
less tailworm-triage.sh          # see for yourself: it only reads
sudo bash tailworm-triage.sh     # Linux (sudo lets it read the daemon's env)
bash tailworm-triage.sh          # macOS
```

(Don't pipe it straight into a shell. The whole point is "calm down and check" — so check the script too.)

## What "vanilla" actually means

| Finding | Needs to be exploitable | Default install |
|---|---|---|
| F1–3, F5 — root via SSH socket-forward (+ the worm) | Tailscale SSH **on** *and* an SSH rule admitting a device | SSH off, no rule |
| F4 — app connector (conn25) | connector configured + advertised | not advertised |
| F6 — headscale unauth DoS / lockout | you **run** headscale | hosted control plane |
| F7 — serve → tailscaled API socket | a `serve --tcp` aimed at the socket | no serve |
| F8 — serve → unix socket | an active serve to a unix socket | no serve |
| F9 — Funnel exposure | Funnel **on** | Funnel off |
| F10 — off-tunnel serve, no ACLs | `TS_SERVE_ALLOW_ALL_INTERFACES` **set** | unset |
| F11 — HTTP/2 per-mount auth race | serve with per-mount auth | no serve |
| Wormability | "policy-granted SSH **plus** F1–3" | no SSH grants |

Nothing here is on by default. Each red line is a decision someone made.

## Fine print

- This triages the report's **own** claims, finding by finding. It is not a hardening tool — it reports, it doesn't change settings.
- The underlying bug *class* is real and was already fixed: advisories **TS-2026-004** and **TS-2026-005** (SSH unix-socket symlink bypass; serve → privileged socket), patched in **Tailscale 1.98.9** (June 2026). A current client already has the fix.
- ACLs, auth keys, and key-expiry live in the control-plane console, not on the node — the script says so where it can't see them.
- Not affiliated with Tailscale.
