/*
 * vuln_permissions.c - the INSECURE permission manager.
 *
 * This is the "before" picture. It looks reasonable at a glance but has four
 * separate access-control weaknesses. Each is tagged VULN-n and matched by a
 * FIX-n note in docs/DESIGN.md, plus a scenario in demo/attacks.sh.
 *
 * DO NOT reuse any of this code.
 *
 * Usage:
 *   vulnctl check  <actor> <action> <resource>
 *   vulnctl login  <username> <role-string>   (client self-reports its role)
 *   vulnctl rename <username> <newname>        (overflow demo)
 *   vulnctl assign <actor> <target> <role>
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* VULN-1: `is_admin` is a plain int sitting right after a fixed-size name
 * buffer. Any overflow of name[] runs straight into the privilege flag. */
struct user {
    char name[16];      /* VULN-3: written with strcpy(), no bounds check   */
    int  is_admin;      /* adjacent privilege flag                          */
    char role[16];      /* VULN-2: role kept as a free-form string          */
};

static struct user users[8];
static int n_users;

static struct user *find(const char *name)
{
    for (int i = 0; i < n_users; ++i)
        if (strcmp(users[i].name, name) == 0)
            return &users[i];
    return NULL;
}

static struct user *add(const char *name, const char *role)
{
    struct user *u = &users[n_users++];
    memset(u, 0, sizeof *u);
    strcpy(u->name, name);              /* VULN-3: unbounded copy           */
    strcpy(u->role, role);              /* VULN-3: unbounded copy           */
    /* VULN-2: prefix compare, so "adminx" counts as admin. */
    u->is_admin = (strncmp(role, "admin", 5) == 0);
    return u;
}

/* VULN-1/VULN-4: the escalated actions are gated ONLY by the is_admin flag,
 * and everything not explicitly forbidden is allowed (allow-by-default). */
static bool check(struct user *u, const char *action, const char *resource)
{
    if (u == NULL)
        return false;
    if (strcmp(action, "manage_users") == 0 || strcmp(resource, "config") == 0)
        return u->is_admin;             /* VULN-1: trusts a flippable flag  */
    if (strcmp(u->role, "guest") == 0)
        return strcmp(action, "read") == 0 && strcmp(resource, "public") == 0;
    return true;                        /* VULN-4: default allow            */
}

/* VULN-3: rename copies attacker input into the 16-byte name with strcpy()
 * and never recomputes is_admin, so a long new name overwrites the adjacent
 * privilege flag and it stays overwritten. */
static void rename_user(struct user *u, const char *newname)
{
    if (u)
        strcpy(u->name, newname);
}

static bool assign(struct user *actor, struct user *target, const char *role)
{
    /* VULN-2: exact compare here, prefix compare in add(): inconsistent. */
    if (actor == NULL || target == NULL || strcmp(actor->role, "admin") != 0)
        return false;
    strcpy(target->role, role);
    target->is_admin = (strncmp(role, "admin", 5) == 0);
    return true;
}

static void seed(void)
{
    add("alice", "admin");
    add("bob",   "user");
    add("eve",   "guest");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fputs("usage: vulnctl check|login|rename|assign ...\n", stderr);
        return 2;
    }
    seed();

    if (strcmp(argv[1], "check") == 0 && argc == 5) {
        bool ok = check(find(argv[2]), argv[3], argv[4]);
        printf("%s\n", ok ? "ALLOWED" : "DENIED");
        return ok ? 0 : 1;
    }
    if (strcmp(argv[1], "login") == 0 && argc == 4) {
        struct user *u = add(argv[2], argv[3]);
        printf("logged in %s role=\"%s\" is_admin=%d\n", u->name, u->role, u->is_admin);
        printf("write config: %s\n", check(u, "write", "config") ? "ALLOWED" : "DENIED");
        printf("manage users: %s\n", check(u, "manage_users", "users") ? "ALLOWED" : "DENIED");
        return 0;
    }
    if (strcmp(argv[1], "rename") == 0 && argc == 4) {
        struct user *u = find(argv[2]);
        if (u == NULL) { puts("no such user"); return 1; }
        printf("before: name=%s is_admin=%d\n", u->name, u->is_admin);
        rename_user(u, argv[3]);
        printf("after : name=%.16s is_admin=%d\n", u->name, u->is_admin);
        printf("manage users now: %s\n",
               check(u, "manage_users", "users") ? "ALLOWED" : "DENIED");
        return 0;
    }
    if (strcmp(argv[1], "assign") == 0 && argc == 5) {
        bool ok = assign(find(argv[2]), find(argv[3]), argv[4]);
        printf("%s\n", ok ? "OK" : "DENIED");
        return ok ? 0 : 1;
    }
    fputs("bad arguments\n", stderr);
    return 2;
}
