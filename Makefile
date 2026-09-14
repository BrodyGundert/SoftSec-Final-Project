# CISE 330 Final Project - Secure Access Control / Permission Manager
CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -Werror -O1 -g -D_POSIX_C_SOURCE=200809L
HARDEN  := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDHARD  := -pie -Wl,-z,relro,-z,now

BIN := build
SRC := src/permissions.c

.PHONY: all clean test demo attacks

all: $(BIN)/permctl $(BIN)/vulnctl $(BIN)/test_permissions

$(BIN):
	mkdir -p $(BIN)

# Hardened build: warnings are errors, stack protector, FORTIFY, PIE, RELRO.
$(BIN)/permctl: src/main.c $(SRC) src/permissions.h | $(BIN)
	$(CC) $(CFLAGS) $(HARDEN) -Isrc -o $@ src/main.c $(SRC) $(LDHARD)

$(BIN)/test_permissions: tests/test_permissions.c $(SRC) src/permissions.h | $(BIN)
	$(CC) $(CFLAGS) $(HARDEN) -Isrc -o $@ tests/test_permissions.c $(SRC) $(LDHARD)

# Vulnerable build: mitigations OFF on purpose so the overflow demo is
# deterministic. -Wno-* lets the intentionally bad code compile; gcc still
# warns about strcpy under -Wall if you drop these flags, which is itself a
# defender lesson (see docs/DESIGN.md).
$(BIN)/vulnctl: vulnerable/vuln_permissions.c | $(BIN)
	$(CC) -std=c11 -O0 -g -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
	      -Wno-stringop-overflow -o $@ $<

test: $(BIN)/test_permissions
	./$(BIN)/test_permissions

demo: $(BIN)/permctl
	./$(BIN)/permctl demo

attacks: all
	./demo/attacks.sh

clean:
	rm -rf $(BIN)
