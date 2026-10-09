# Secure Access Control / Permission Manager

CISE 330 Software Security - final project (Option #5). A small C access-control
system built to show, side by side, how an attacker escalates privileges and how
a defender closes each hole.

> Coursework repository for CISE 330. See `docs/DESIGN.md` for the full writeup.

## What it does

Manages users with roles (`admin`, `user`, `guest`) and answers one question
safely: *may this role perform this action on this resource?* It ships a
**vulnerable** program and a **hardened** rewrite so the contrast is concrete.

## Quick start

```sh
make all       # permctl (hardened), vulnctl (vulnerable), test binary
make test      # run the test suite
make attacks   # attacker-vs-defender walkthrough
```

## Run in Docker

```sh
docker build -t permctl .          # compiles + runs tests inside the image
docker run --rm permctl            # guided demo
docker run --rm permctl attacks    # attacker-vs-defender walkthrough
docker run --rm permctl check eve delete config   # single decision
```

The image is a multi-stage build: a `gcc` stage compiles with the hardened
flags and runs the test suite, then a slim Debian stage carries only the
binaries and runs as a non-root user.

## Layout

| Path                              | What it is                                        |
|-----------------------------------|---------------------------------------------------|
| `src/permissions.{h,c}`           | hardened permission manager (the deliverable)     |
| `src/main.c`                      | `permctl` CLI + guided demo                       |
| `vulnerable/vuln_permissions.c`   | intentionally insecure `vulnctl` (the "before")   |
| `tests/test_permissions.c`        | assertion-based test suite                        |
| `demo/attacks.sh`                 | runs each exploit, then the hardened refusal      |
| `docs/DESIGN.md`                  | threat model, security properties, CWE mapping    |

## Security properties (short version)

Deny-by-default policy table, a single un-bypassable check path, boundary
validation of role strings, opaque user records with a keyed integrity tag so a
role cannot be forged or flipped, and audit logging of every denial. Details and
the weakness→fix table are in `docs/DESIGN.md`.
