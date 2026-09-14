/*
 * permissions.c - hardened permission manager. See permissions.h for the
 * design rules; the comments below point at the specific weakness in
 * vulnerable/vuln_permissions.c that each piece closes.
 */
#include "permissions.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Policy table: role x resource -> allowed action bitmask.             */
/* Anything not listed here is denied. ROLE_INVALID has an all-zero row */
/* so even an out-of-range lookup that somehow lands there gets nothing. */
/* ------------------------------------------------------------------ */
static const unsigned POLICY[ROLE_COUNT][RES_COUNT] = {
    /*                 PUBLIC     USERDATA               CONFIG                 USERS */
    [ROLE_INVALID] = { 0,         0,                     0,                     0 },
    [ROLE_GUEST]   = { ACT_READ,  0,                     0,                     0 },
    [ROLE_USER]    = { ACT_READ,  ACT_READ | ACT_WRITE,  ACT_READ,              0 },
    [ROLE_ADMIN]   = { ACT_READ | ACT_WRITE | ACT_DELETE,
                       ACT_READ | ACT_WRITE | ACT_DELETE,
                       ACT_READ | ACT_WRITE | ACT_DELETE,
                       ACT_READ | ACT_MANAGE_USERS },
};

/* ------------------------------------------------------------------ */
/* User table. Layout is private to this file (opaque type).            */
/* ------------------------------------------------------------------ */
#define USER_ID_MAX 32u
#define MAX_USERS   16u

struct user {
    char     id[USER_ID_MAX];
    role_t   role;
    uint64_t tag;     /* integrity tag over (id, role), keyed */
    bool     in_use;
};

static struct user g_users[MAX_USERS];
static uint64_t    g_key;          /* per-process secret for the tag */
static unsigned    g_denials;

/* ------------------------------------------------------------------ */
/* Integrity tag. This is a keyed FNV-1a style hash, NOT a real MAC;    */
/* it is enough to demonstrate the property "flipping the role byte    */
/* without knowing the key is detected". A production system would use */
/* HMAC-SHA256 (or, better, never let untrusted code near the record). */
/* ------------------------------------------------------------------ */
static uint64_t compute_tag(const char *id, role_t role)
{
    uint64_t h = 1469598103934665603ULL ^ g_key;
    for (const unsigned char *p = (const unsigned char *)id; *p; ++p) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    h ^= (uint64_t)role;
    h *= 1099511628211ULL;
    h ^= g_key >> 17;
    return h;
}

static void seal(struct user *u)
{
    u->tag = compute_tag(u->id, u->role);
}

static bool record_ok(const struct user *u)
{
    if (u == NULL || !u->in_use)
        return false;
    if (u->role <= ROLE_INVALID || u->role >= ROLE_COUNT)   /* range check */
        return false;
    return compute_tag(u->id, u->role) == u->tag;
}

/* ------------------------------------------------------------------ */
/* Logging                                                              */
/* ------------------------------------------------------------------ */
static void audit(const char *verdict, const char *who, action_t a,
                  resource_t r, const char *reason)
{
    time_t now = time(NULL);
    struct tm tmv;
    char ts[32] = "unknown-time";
    if (localtime_r(&now, &tmv))
        strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);
    /* Every field is printed through a format *we* control: no
     * printf(user_string) format-string bug here (cf. Lab 1). */
    fprintf(stderr, "[%s] %s actor=%s action=%s resource=%s reason=%s\n",
            ts, verdict, who ? who : "(null)", action_name(a),
            resource_name(r), reason);
}

/* ------------------------------------------------------------------ */
/* Role parsing                                                         */
/* ------------------------------------------------------------------ */
role_t role_from_string(const char *s)
{
    if (s == NULL)
        return ROLE_INVALID;

    /* Bounded scan: never read past ROLE_NAME_MAX. Reject anything longer,
     * which also rejects the "admin<padding>" prefix tricks. */
    size_t len = strnlen(s, ROLE_NAME_MAX);
    if (len == 0 || len >= ROLE_NAME_MAX)
        return ROLE_INVALID;

    /* Trim ASCII whitespace on both ends. */
    size_t start = 0, end = len;
    while (start < end && isspace((unsigned char)s[start]))
        start++;
    while (end > start && isspace((unsigned char)s[end - 1]))
        end--;
    if (start == end)
        return ROLE_INVALID;

    /* Normalise to lowercase into a local buffer; reject any byte that is
     * not a plain ASCII letter (no digits, punctuation, control chars,
     * high-bit bytes). */
    char norm[ROLE_NAME_MAX] = {0};
    size_t n = 0;
    for (size_t i = start; i < end; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x80 || !isalpha(c))
            return ROLE_INVALID;
        norm[n++] = (char)tolower(c);
    }
    norm[n] = '\0';

    /* Exact-match allowlist. strcmp on the *whole* string, not a prefix. */
    if (strcmp(norm, "guest") == 0) return ROLE_GUEST;
    if (strcmp(norm, "user")  == 0) return ROLE_USER;
    if (strcmp(norm, "admin") == 0) return ROLE_ADMIN;
    return ROLE_INVALID;
}

const char *role_name(role_t r)
{
    switch (r) {
    case ROLE_GUEST: return "guest";
    case ROLE_USER:  return "user";
    case ROLE_ADMIN: return "admin";
    default:         return "invalid";
    }
}

const char *action_name(action_t a)
{
    switch (a) {
    case ACT_READ:         return "read";
    case ACT_WRITE:        return "write";
    case ACT_DELETE:       return "delete";
    case ACT_MANAGE_USERS: return "manage_users";
    default:               return "unknown-action";
    }
}

const char *resource_name(resource_t r)
{
    switch (r) {
    case RES_PUBLIC:   return "public";
    case RES_USERDATA: return "userdata";
    case RES_CONFIG:   return "config";
    case RES_USERS:    return "users";
    default:           return "unknown-resource";
    }
}

/* ------------------------------------------------------------------ */
/* User table management                                                */
/* ------------------------------------------------------------------ */
void perm_init(void)
{
    memset(g_users, 0, sizeof g_users);
    g_denials = 0;

    /* Best-effort key: /dev/urandom, falling back to time+address mixing.
     * The demo does not rely on cryptographic strength, only on the key
     * being unknown to code that tampers with a record. */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL || fread(&g_key, sizeof g_key, 1, f) != 1)
        g_key = (uint64_t)time(NULL) ^ ((uint64_t)(uintptr_t)&g_key << 13);
    if (f)
        fclose(f);
    if (g_key == 0)
        g_key = 0x9E3779B97F4A7C15ULL;
}

static bool id_ok(const char *id)
{
    if (id == NULL)
        return false;
    size_t len = strnlen(id, USER_ID_MAX);
    if (len == 0 || len >= USER_ID_MAX)
        return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)id[i];
        if (c >= 0x80 || !(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return false;
    }
    return true;
}

user_t *user_bootstrap(const char *id, role_t role)
{
    if (!id_ok(id) || role <= ROLE_INVALID || role >= ROLE_COUNT)
        return NULL;
    if (user_find(id) != NULL)
        return NULL;                       /* no duplicate ids */
    for (unsigned i = 0; i < MAX_USERS; ++i) {
        if (!g_users[i].in_use) {
            struct user *u = &g_users[i];
            memset(u, 0, sizeof *u);
            /* Bounded copy; id_ok() already guarantees it fits. */
            snprintf(u->id, sizeof u->id, "%s", id);
            u->role = role;
            u->in_use = true;
            seal(u);
            return u;
        }
    }
    return NULL;
}

user_t *user_find(const char *id)
{
    if (!id_ok(id))
        return NULL;
    for (unsigned i = 0; i < MAX_USERS; ++i)
        if (g_users[i].in_use && strcmp(g_users[i].id, id) == 0)
            return &g_users[i];
    return NULL;
}

const char *user_id(const user_t *u)
{
    return (u && u->in_use) ? u->id : "(none)";
}

role_t user_role(const user_t *u)
{
    return record_ok(u) ? u->role : ROLE_INVALID;
}

/* ------------------------------------------------------------------ */
/* THE decision point                                                   */
/* ------------------------------------------------------------------ */
bool access_check(const user_t *actor, action_t action, resource_t resource)
{
    const char *who = user_id(actor);

    /* 1. Reject anything that is not a live, sealed record. */
    if (actor == NULL || !actor->in_use) {
        g_denials++;
        audit("DENY", who, action, resource, "no-such-user");
        return false;
    }
    if (!record_ok(actor)) {
        g_denials++;
        audit("DENY", who, action, resource, "tampered-or-invalid-role");
        return false;
    }

    /* 2. Bounds-check the resource before indexing the table. */
    if ((unsigned)resource >= RES_COUNT) {
        g_denials++;
        audit("DENY", who, action, resource, "unknown-resource");
        return false;
    }

    /* 3. Exactly-one-bit action, otherwise someone is trying to smuggle a
     *    combined mask through (e.g. READ|MANAGE_USERS). */
    unsigned a = (unsigned)action;
    if (a == 0 || (a & (a - 1)) != 0) {
        g_denials++;
        audit("DENY", who, action, resource, "malformed-action");
        return false;
    }

    /* 4. Table lookup. Deny unless the bit is explicitly present. */
    bool allowed = (POLICY[actor->role][resource] & a) != 0;
    if (!allowed) {
        g_denials++;
        audit("DENY", who, action, resource, "policy");
        return false;
    }
    audit("ALLOW", who, action, resource, "policy");
    return true;
}

bool assign_role(const user_t *actor, user_t *target, role_t new_role)
{
    /* Same choke point as everything else: no special-case path. */
    if (!access_check(actor, ACT_MANAGE_USERS, RES_USERS))
        return false;
    if (target == NULL || !target->in_use)
        return false;
    if (new_role <= ROLE_INVALID || new_role >= ROLE_COUNT)
        return false;
    fprintf(stderr, "[audit] %s set role of %s: %s -> %s\n",
            user_id(actor), user_id(target),
            role_name(user_role(target)), role_name(new_role));
    target->role = new_role;
    seal(target);
    return true;
}

unsigned perm_denials(void)
{
    return g_denials;
}
