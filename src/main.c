/*
 * main.c - small command-line driver for the hardened permission manager.
 *
 * Usage:
 *   permctl check <actor-id> <action> <resource>
 *   permctl assign <actor-id> <target-id> <new-role>
 *   permctl demo
 *
 * Seeded users: alice=admin, bob=user, eve=guest.
 * Exit status: 0 = allowed / success, 1 = denied, 2 = usage error.
 */
#include "permissions.h"

#include <stdio.h>
#include <string.h>

static action_t parse_action(const char *s)
{
    if (s == NULL) return 0;
    if (strcmp(s, "read") == 0)         return ACT_READ;
    if (strcmp(s, "write") == 0)        return ACT_WRITE;
    if (strcmp(s, "delete") == 0)       return ACT_DELETE;
    if (strcmp(s, "manage_users") == 0) return ACT_MANAGE_USERS;
    return 0;                     /* 0 is rejected by access_check() */
}

static resource_t parse_resource(const char *s)
{
    if (s == NULL) return RES_COUNT;
    if (strcmp(s, "public") == 0)   return RES_PUBLIC;
    if (strcmp(s, "userdata") == 0) return RES_USERDATA;
    if (strcmp(s, "config") == 0)   return RES_CONFIG;
    if (strcmp(s, "users") == 0)    return RES_USERS;
    return RES_COUNT;             /* out of range -> denied */
}

static void seed(void)
{
    perm_init();
    user_bootstrap("alice", ROLE_ADMIN);
    user_bootstrap("bob",   ROLE_USER);
    user_bootstrap("eve",   ROLE_GUEST);
}

static int usage(void)
{
    fputs("usage: permctl check <actor> <action> <resource>\n"
          "       permctl assign <actor> <target> <role>\n"
          "       permctl demo\n"
          "actions: read write delete manage_users\n"
          "resources: public userdata config users\n", stderr);
    return 2;
}

static int do_check(const char *actor, const char *act, const char *res)
{
    bool ok = access_check(user_find(actor), parse_action(act), parse_resource(res));
    printf("%s\n", ok ? "ALLOWED" : "DENIED");
    return ok ? 0 : 1;
}

static int do_assign(const char *actor, const char *target, const char *role)
{
    role_t r = role_from_string(role);
    if (r == ROLE_INVALID) {
        printf("DENIED (invalid role string)\n");
        return 1;
    }
    bool ok = assign_role(user_find(actor), user_find(target), r);
    printf("%s\n", ok ? "OK" : "DENIED");
    return ok ? 0 : 1;
}

static int do_demo(void)
{
    puts("-- hardened build demo --");
    puts("1. guest reads public page:");
    do_check("eve", "read", "public");
    puts("2. guest tries to delete config (privilege escalation attempt):");
    do_check("eve", "delete", "config");
    puts("3. user tries to promote themself to admin:");
    do_assign("bob", "bob", "admin");
    puts("4. admin promotes bob, then bob can write config:");
    do_assign("alice", "bob", "admin");
    do_check("bob", "write", "config");
    puts("5. malformed / unknown role strings are rejected:");
    const char *bad[] = { "root", "adminx", "superuser", "admin;drop", "", "gu est", NULL };
    for (int i = 0; bad[i]; ++i)
        printf("   role_from_string(\"%s\") -> %s\n", bad[i], role_name(role_from_string(bad[i])));
    puts("6. only whitespace and letter-case are normalised (still exact match):");
    const char *ok[] = { "  ADMIN ", "Guest", "user\t", NULL };
    for (int i = 0; ok[i]; ++i)
        printf("   role_from_string(\"%s\") -> %s\n", ok[i], role_name(role_from_string(ok[i])));
    printf("denials logged: %u\n", perm_denials());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage();
    seed();
    if (strcmp(argv[1], "check") == 0 && argc == 5)
        return do_check(argv[2], argv[3], argv[4]);
    if (strcmp(argv[1], "assign") == 0 && argc == 5)
        return do_assign(argv[2], argv[3], argv[4]);
    if (strcmp(argv[1], "demo") == 0)
        return do_demo();
    return usage();
}
