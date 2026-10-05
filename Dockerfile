# syntax=docker/dockerfile:1
#
# Multi-stage build for the CISE 330 permission manager.
#
#   Stage 1 (build): compile everything with the hardened flags and RUN the
#                    test suite, so the image fails to build if tests fail.
#   Stage 2 (run):   a slim runtime image carrying only the built binaries.
#
# Build:  docker build -t permctl .
# Run:    docker run --rm permctl            # runs the guided demo
#         docker run --rm permctl check eve read public
#         docker run --rm permctl attacks    # attacker-vs-defender walkthrough

# ---- build stage ----------------------------------------------------------
FROM gcc:13 AS build
WORKDIR /app
COPY . .
# make test builds the test binary and runs it; a failure stops the image.
RUN make all && make test

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# Run as a non-root user: nothing here needs privileges.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=build /app/build/ ./build/
COPY --from=build /app/demo/attacks.sh ./demo/attacks.sh
# Tiny entrypoint: no args -> demo; "attacks" -> walkthrough; else pass to permctl.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'case "$1" in' \
    '  "")        exec /app/build/permctl demo ;;' \
    '  attacks)   exec /app/demo/attacks.sh ;;' \
    '  *)         exec /app/build/permctl "$@" ;;' \
    'esac' > /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh
USER appuser
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
