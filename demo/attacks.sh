#!/usr/bin/env bash
# attacks.sh - attacker's view. Each exploit runs against the VULNERABLE
# binary, then the hardened binary is shown refusing the same thing.
# Run from the repo root:  ./demo/attacks.sh   (or:  make attacks)
set -u
B=build
V="$B/vulnctl"
P="$B/permctl"

hr(){ printf '\n=== %s ===\n' "$1"; }

if [ ! -x "$V" ] || [ ! -x "$P" ]; then
    echo "build first: make all" >&2
    exit 1
fi

hr "ATTACK 1: self-reported role (client sends role=admin)"
echo "[vuln] the server believes whatever role string it is handed:"
"$V" login mallory admin
echo "[safe] user role strings are validated; there is no 'log in as admin'."
echo "       admin is only reachable via assign_role() by an existing admin:"
"$P" assign mallory nobody admin       # mallory is not a real user -> DENIED

hr "ATTACK 2: unknown role slips through (allow-by-default)"
echo "[vuln] an unrecognised role is not 'guest', so default-allow lets it act:"
"$V" login weirdo lieutenant
echo "[safe] unknown role -> ROLE_INVALID -> denied everything (deny-by-default):"
"$P" check eve manage_users users

hr "ATTACK 3: prefix / case confusion ('adminx', 'Admin ')"
echo "[vuln] add() uses strncmp(role,\"admin\",5), so 'adminx' is treated as admin:"
"$V" login sneaky adminx
echo "[safe] exact allowlist match, so 'adminx'/'superuser'/'admin;drop' all reject"
echo "       (only whitespace and case are normalised):"
"$P" demo | sed -n '/malformed .* rejected/,/-> admin (whitespace/p' | sed -n '/role_from_string/p'

hr "ATTACK 4: buffer overflow flips the is_admin flag"
echo "[vuln] bob is a normal 'user' (is_admin=0). rename() strcpy()s into"
echo "       name[16]; a 20-char name overruns into the adjacent is_admin int:"
"$V" rename bob AAAAAAAAAAAAAAAAAAAA
echo "[safe] hardened ids are length/charset checked and the role lives behind"
echo "       an integrity tag, so no overflow or direct write can forge admin:"
"$P" check bob manage_users users

hr "SUMMARY"
echo "The vulnerable binary granted escalated access in attacks 1, 3 and 4"
echo "and default-allowed in attack 2. The hardened binary denied every one."
echo "See docs/DESIGN.md for the full weakness -> fix mapping."
