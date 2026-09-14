/*
 * test_permissions.c - assertion-based tests for the hardened manager.
 * No framework: each check prints PASS/FAIL and the process exits non-zero
 * if anything failed, so `make test` fails loudly in CI (GitLab).
 */
#include "permissions.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg) do {                                   \
    if (cond) { printf("  PASS: %s\n", msg); }                  \
    else      { printf("  FAIL: %s\n", msg); failures++; }      \
} while (0)

static void test_role_parsing(void)
{
    puts("role_from_string():");
    CHECK(role_from_string("guest") == ROLE_GUEST, "\"guest\" -> guest");
    CHECK(role_from_string("user")  == ROLE_USER,  "\"user\" -> user");
    CHECK(role_from_string("admin") == ROLE_ADMIN, "\"admin\" -> admin");
    CHECK(role_from_string("  ADMIN ") == ROLE_ADMIN, "whitespace+case normalised");
    CHECK(role_from_string(NULL)    == ROLE_INVALID, "NULL -> invalid");
    CHECK(role_from_string("")      == ROLE_INVALID, "empty -> invalid");
    CHECK(role_from_string("root")  == ROLE_INVALID, "\"root\" -> invalid");
    CHECK(role_from_string("adminx")== ROLE_INVALID, "no prefix match (\"adminx\")");
    CHECK(role_from_string("admin;drop") == ROLE_INVALID, "punctuation rejected");
    CHECK(role_from_string("admin\textra") == ROLE_INVALID, "trailing token rejected");
    CHECK(role_from_string("superuseradminadmin") == ROLE_INVALID, "over-long -> invalid");
}

static void test_deny_by_default(void)
{
    puts("deny-by-default & policy:");
    perm_init();
    user_t *admin = user_bootstrap("root_admin", ROLE_ADMIN);
    user_t *usr   = user_bootstrap("normal",     ROLE_USER);
    user_t *guest = user_bootstrap("visitor",    ROLE_GUEST);

    CHECK(access_check(guest, ACT_READ, RES_PUBLIC), "guest reads public");
    CHECK(!access_check(guest, ACT_WRITE, RES_PUBLIC), "guest cannot write public");
    CHECK(!access_check(guest, ACT_DELETE, RES_CONFIG), "guest cannot delete config");
    CHECK(!access_check(guest, ACT_MANAGE_USERS, RES_USERS), "guest cannot manage users");

    CHECK(access_check(usr, ACT_WRITE, RES_USERDATA), "user writes own data");
    CHECK(!access_check(usr, ACT_WRITE, RES_CONFIG), "user cannot write config");
    CHECK(!access_check(usr, ACT_MANAGE_USERS, RES_USERS), "user cannot manage users");

    CHECK(access_check(admin, ACT_MANAGE_USERS, RES_USERS), "admin manages users");
    CHECK(access_check(admin, ACT_DELETE, RES_CONFIG), "admin deletes config");

    CHECK(!access_check(NULL, ACT_READ, RES_PUBLIC), "NULL actor denied");
}

static void test_malformed_inputs(void)
{
    puts("malformed action/resource:");
    perm_init();
    user_t *admin = user_bootstrap("a", ROLE_ADMIN);
    /* combined mask must be rejected (single-bit rule) */
    CHECK(!access_check(admin, (action_t)(ACT_READ | ACT_MANAGE_USERS), RES_USERS),
          "combined action mask denied");
    CHECK(!access_check(admin, (action_t)0, RES_PUBLIC), "zero action denied");
    CHECK(!access_check(admin, ACT_READ, (resource_t)999), "out-of-range resource denied");
}

static void test_tamper_detection(void)
{
    puts("tamper detection & escalation:");
    perm_init();
    user_t *admin = user_bootstrap("boss", ROLE_ADMIN);
    user_t *guest = user_bootstrap("mallory", ROLE_GUEST);

    /* Attacker flips the role field directly, bypassing assign_role(). */
    struct raw { char id[32]; int role; } ; /* not the real layout, just to prove opacity */
    (void)sizeof(struct raw);

    /* We cannot see struct user's layout from here (opaque), which is the
     * point. Simulate tampering via the only handle we have by memcpy over
     * the bytes the pointer refers to. */
    unsigned char *bytes = (unsigned char *)guest;
    /* find the role enum (value 1 == ROLE_GUEST) somewhere after the id */
    int patched = 0;
    for (size_t i = 0; i < 64; ++i) {
        int *slot = (int *)(bytes + i);
        if (*slot == ROLE_GUEST) { *slot = ROLE_ADMIN; patched = 1; break; }
    }
    CHECK(patched, "located and flipped role byte (simulated attack)");
    CHECK(user_role(guest) == ROLE_INVALID, "tampered record reads as INVALID");
    CHECK(!access_check(guest, ACT_MANAGE_USERS, RES_USERS),
          "tampered guest still denied admin action");

    /* Legitimate promotion through the choke point keeps the tag valid. */
    perm_init();
    admin = user_bootstrap("boss", ROLE_ADMIN);
    user_t *bob = user_bootstrap("bob", ROLE_USER);
    CHECK(!assign_role(bob, bob, ROLE_ADMIN), "user cannot self-promote");
    CHECK(assign_role(admin, bob, ROLE_ADMIN), "admin promotes user");
    CHECK(access_check(bob, ACT_MANAGE_USERS, RES_USERS), "promoted user now allowed");
}

int main(void)
{
    test_role_parsing();
    test_deny_by_default();
    test_malformed_inputs();
    test_tamper_detection();
    printf("\n%s (%d failure%s)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
