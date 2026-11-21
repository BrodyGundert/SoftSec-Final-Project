#!/usr/bin/env bash
# fuzz.sh - simple dynamic / fuzz testing for the hardened permission manager.
#
# Feeds random and malformed arguments to permctl and checks the program never
# CRASHES (no segfault or other signal kill). A normal ALLOWED/DENIED/usage
# result is fine; being killed by a signal is not. Run from the repo root:
#   ./tests/fuzz.sh      (or: make fuzz)
set -u

BIN=build/permctl
if [ ! -x "$BIN" ]; then
    echo "building first..."; make all >/dev/null || { echo "build failed"; exit 1; }
fi

iterations="${1:-500}"
actions=(read write delete manage_users check assign demo "" "../../etc/passwd" "%s%s%s%n" "admin;drop")
resources=(public userdata config users "" "A" "-1" "999999")
roles=(admin user guest adminx "  ADMIN " "root" "" "$(head -c 80 /dev/zero | tr '\0' 'A')" "a;b|c")

rand() { local arr=("$@"); echo "${arr[$((RANDOM % ${#arr[@]}))]}"; }

fail=0
crash() {
    # exit codes >= 128 mean killed by a signal (e.g. 139 = SIGSEGV).
    [ "$1" -ge 128 ]
}

for i in $(seq 1 "$iterations"); do
    a=$(rand "${actions[@]}")
    r=$(rand "${resources[@]}")
    u=$(rand "${roles[@]}")
    # exercise all three subcommands with fuzzed arguments
    "$BIN" check "$u" "$a" "$r"  >/dev/null 2>&1; rc=$?; crash $rc && { echo "CRASH: check '$u' '$a' '$r' -> $rc"; fail=1; }
    "$BIN" assign "$u" "$u" "$a" >/dev/null 2>&1; rc=$?; crash $rc && { echo "CRASH: assign '$u' '$u' '$a' -> $rc"; fail=1; }
    "$BIN" "$a" "$u" "$r" "$u"   >/dev/null 2>&1; rc=$?; crash $rc && { echo "CRASH: raw '$a' '$u' '$r' '$u' -> $rc"; fail=1; }
done

# a few explicit nasty inputs
for bad in "$(head -c 5000 /dev/zero | tr '\0' 'A')" "%n%n%n%n" "../../../../etc/shadow" "-----"; do
    "$BIN" check "$bad" read public >/dev/null 2>&1; rc=$?; crash $rc && { echo "CRASH on oversized/malformed role"; fail=1; }
done

if [ "$fail" -eq 0 ]; then
    echo "FUZZ PASSED: $iterations iterations, no crashes"
    exit 0
else
    echo "FUZZ FAILED: a crash was detected"
    exit 1
fi
