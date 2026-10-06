# Secure Access Control / Permission Manager - Design

CISE 330 Software Security, Final Project (Option #5). Brody Gundert.

The project manages users with roles (`admin`, `user`, `guest`) and answers
one question safely: *may this role perform this action on this resource?*
It ships two programs so both perspectives are visible side by side:

- `vulnctl` (`vulnerable/vuln_permissions.c`) - the **attacker's** playground.
  Four realistic access-control weaknesses.
- `permctl` (`src/`) - the **defender's** hardened rewrite that closes them.

`demo/attacks.sh` runs each exploit against `vulnctl`, then shows `permctl`
refusing the same thing. `tests/test_permissions.c` locks the behaviour in.

## Threat model

An attacker can call the API with arbitrary arguments and can, in the worst
case, corrupt process memory (the buffer-overflow case). The goal is
**privilege escalation**: a guest or user performing an admin-only action.
We defend against: forged/self-reported roles, unknown or malformed roles,
inconsistent role comparisons, and direct tampering with a role/flag in
memory.

## Security properties (defender)

1. **Deny by default.** The policy table (`POLICY[role][resource]`) lists
   only what is *allowed*; every path that is not an explicit grant returns
   `false`. `ROLE_INVALID` has an all-zero row.
2. **One choke point.** Every decision - including `assign_role()` - goes
   through `access_check()`. There is no second code path that can disagree
   with it (the vulnerable version had exactly that split-brain bug).
3. **Validate at the boundary.** Untrusted strings become a `role_t` only via
   `role_from_string()`, an exact allowlist match after trimming whitespace
   and lowercasing. Length-bounded (`strnlen`), charset-restricted (letters
   only), no prefix matching.
4. **Roles are unforgeable.** `struct user` is opaque; callers get a
   `user_t *` and cannot read or write the role field. The only way to change
   a role is `assign_role()`, which itself requires `MANAGE_USERS` on
   `RES_USERS`.
5. **Tamper detection.** Each record carries a keyed integrity tag over
   `(id, role)`. A record whose tag does not recompute is treated as
   `ROLE_INVALID` and denied. (Demonstration-grade keyed hash, not a real
   MAC - a production system would use HMAC-SHA256, or keep untrusted code
   away from the record entirely.)
6. **Fail safe & log.** Malformed actions (zero bits or multiple bits),
   out-of-range resources, NULL actors, and tampered records are all denied,
   and every denial is written to the audit log with a reason.

## Weakness → fix mapping

| # | Vulnerable (`vuln_permissions.c`)                              | Attack shown                        | Hardened fix (`permissions.c`)                                   |
|---|----------------------------------------------------------------|-------------------------------------|------------------------------------------------------------------|
| 1 | `is_admin` int adjacent to a fixed buffer; trusted directly    | overflow name[] to flip `is_admin`  | opaque record + keyed integrity tag; range-checked enum role     |
| 2 | role stored as a string, compared with `strncmp(...,5)`        | `adminx` counts as admin            | `role_from_string()` exact allowlist; role is an enum thereafter |
| 3 | `strcpy()` into `name[16]`/`role[16]`                          | 20-char name overruns the flag      | `strnlen`/`snprintf`, id charset + length validation             |
| 4 | allow-by-default (`return true` at the end of `check`)         | unknown role `lieutenant` allowed   | deny-by-default policy table; unknown role → `ROLE_INVALID`      |

## Build & run

```
make all       # builds permctl, vulnctl, and the test binary
make test      # runs the assertion suite (fails non-zero on any failure)
make demo      # permctl's own guided demo
make attacks   # the attacker-vs-defender walkthrough
```

The hardened build uses `-Wall -Wextra -Werror`, `-fstack-protector-strong`,
`-D_FORTIFY_SOURCE=2`, and `-pie -Wl,-z,relro,-z,now`. The vulnerable build
deliberately disables these so the overflow is reproducible; note that even
plain `gcc -Wall` warns about the `strcpy`/`strncpy` misuse, which is itself
the first line of defence.

## Mapping to CWE

- CWE-862 Missing Authorization / CWE-863 Incorrect Authorization (VULN-4)
- CWE-269 Improper Privilege Management (VULN-1, VULN-2)
- CWE-120/CWE-787 Buffer Copy without Size Check / Out-of-bounds Write (VULN-3)
