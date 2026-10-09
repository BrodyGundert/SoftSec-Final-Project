# Midterm Demo Runbook

A step-by-step script for the 10-minute live demo. Frame it as progress:
the core engine works; the written report and some hardening are still to come.

Open two things before you start:
- A terminal in the project folder (`cd ~/SoftSec-Final-Project`).
- A browser tab on the GitLab project, Build > Pipelines page.

---

## 1. Repository and commit history  (~1 min)

Show the GitLab repo page, then in the terminal:

```
git log --oneline
```

Talking point: "Seven commits showing steady progress, from the core engine,
to Docker, to CI, to cleanup. Each commit is one focused change."

Then show the layout:

```
ls
```

Point out: `src/` (hardened code), `vulnerable/` (the attack target),
`tests/`, `demo/`, `docs/`, plus `Dockerfile` and `.gitlab-ci.yml`.

---

## 2. Build and run the code  (~2 min)

```
make all
```

Talking point: "One command builds the hardened tool, the vulnerable tool,
and the test binary, with warnings treated as errors."

Run a few live decisions:

```
./build/permctl check eve read public     # guest reading public  -> ALLOWED
./build/permctl check eve delete config    # guest deleting config -> DENIED
./build/permctl assign alice bob adminx    # bad role string       -> DENIED
./build/permctl assign alice bob admin     # admin promotes bob    -> OK
```

Talking point: "Every decision goes through one function. Deny by default."

---

## 3. The tests  (~1 min)

```
make test
```

Talking point: "Thirty automated checks, all passing. This runs in CI too,
so a broken change fails the pipeline."

---

## 4. Attacker vs defender  (~3 min, the centerpiece)

```
make attacks
```

Walk through the four attacks as they scroll:
1. Self-reported role = admin: vulnerable believes it, hardened denies.
2. Unknown role: vulnerable allows by default, hardened denies.
3. Prefix trick "adminx": vulnerable treats it as admin, hardened rejects.
4. Buffer overflow flips is_admin: vulnerable escalates, hardened denies.

Talking point: "Same four attacks, run against both builds. The vulnerable
build escalates, the hardened build blocks every one, and logs each denial."

Point at the `DENY ... reason=...` lines: "That is the audit log, the
defender seeing every blocked attempt."

---

## 5. CI/CD pipeline  (~1.5 min)

Switch to the GitLab Pipelines tab. Show the green pipeline with stages
build > test > docker > security.

Then show the warning flags in the config:

```
grep WARNING_FLAGS .gitlab-ci.yml
```

Talking point: "Four stages on every push. These warning flags, with
-Werror, mean any compiler warning fails the build."

---

## 6. Docker  (~1 min)

```
docker build -t permctl .
docker run --rm permctl check eve delete config
```

Talking point: "Multi-stage image: it compiles and runs the tests inside the
build stage, then ships only the binaries in a slim runtime image that runs
as a non-root user."

---

## 7. What is done and what is next  (~1 min, closing)

Done: core engine, four-attack demo, tests, CI/CD, Docker.

Still in progress (say this out loud, it is a midterm):
- Written report with the full threat model and CWE mapping.
- Replace the demonstration integrity tag with real HMAC-SHA256.
- More edge-case tests for role and resource combinations.

Close: "The security core works end to end today. The remaining work is
documentation and one hardening upgrade."

---

## If something breaks on stage

- Build fails: run `make clean` then `make all`.
- Docker daemon not running: `sudo systemctl start docker` (or start Docker Desktop).
- Pipeline shows pending forever: shared runners, enable under GitLab
  Settings > CI/CD > Runners. Have a screenshot of a past green run as backup.
- Always have a screen recording or screenshots as a fallback if the network
  or a runner misbehaves live.
