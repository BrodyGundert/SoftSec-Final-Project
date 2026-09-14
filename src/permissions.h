/*
 * permissions.h - Secure Access Control / Permission Manager (hardened build)
 *
 * Design rules (see docs/DESIGN.md):
 *   1. Deny by default: nothing is allowed unless the policy table says so.
 *   2. One choke point: every decision goes through access_check(). There is
 *      no other way to ask "is this allowed?".
 *   3. Roles are validated on entry: untrusted strings become a role_t only
 *      through role_from_string(), which rejects anything not on the list.
 *   4. Users are opaque: callers cannot see or touch the role field. The only
 *      way to change a role is assign_role(), which itself goes through
 *      access_check() (an actor needs MANAGE_USERS on RES_USERS).
 *   5. Tamper detection: each user record carries an integrity tag over
 *      (id, role). A record whose tag does not match is treated as invalid
 *      and denied.
 */
#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Roles. ROLE_INVALID is the sentinel for "unknown / malformed / tampered". */
typedef enum {
    ROLE_INVALID = 0,
    ROLE_GUEST   = 1,
    ROLE_USER    = 2,
    ROLE_ADMIN   = 3,
    ROLE_COUNT   = 4
} role_t;

/* Actions are bits so a policy cell is a small bitmask. */
typedef enum {
    ACT_READ         = 1u << 0,
    ACT_WRITE        = 1u << 1,
    ACT_DELETE       = 1u << 2,
    ACT_MANAGE_USERS = 1u << 3
} action_t;

typedef enum {
    RES_PUBLIC = 0,   /* e.g. public pages */
    RES_USERDATA,     /* a signed-in user's own data */
    RES_CONFIG,       /* system configuration */
    RES_USERS,        /* the user/role table itself */
    RES_COUNT
} resource_t;

/* Opaque user handle: the struct layout lives only in permissions.c. */
typedef struct user user_t;

#define ROLE_NAME_MAX 16u   /* longest accepted role string incl. NUL */

/* --- Role parsing ----------------------------------------------------- */

/* Parse an untrusted role string. Accepts exactly "guest", "user", "admin"
 * after trimming ASCII whitespace and lowercasing. Anything else (NULL,
 * empty, too long, embedded control chars, "Admin ", "admin\0x", "root",
 * "superuser", "admin;drop"...) yields ROLE_INVALID.
 */
role_t role_from_string(const char *s);

/* Stable printable name; never NULL. Unknown values print as "invalid". */
const char *role_name(role_t r);
const char *action_name(action_t a);
const char *resource_name(resource_t r);

/* --- User table ------------------------------------------------------- */

/* One-time init. Seeds the integrity key. Call before anything else. */
void perm_init(void);

/* Bootstrap: create a user with a given role WITHOUT an authorisation check.
 * Only for seeding the initial admin at startup (before any untrusted input
 * exists). Returns NULL if the table is full or role is invalid.
 */
user_t *user_bootstrap(const char *id, role_t role);

/* Look up a user by id. NULL if not found. */
user_t *user_find(const char *id);

const char *user_id(const user_t *u);
role_t      user_role(const user_t *u);   /* ROLE_INVALID if tampered/NULL */

/* --- The single decision point --------------------------------------- */

/* Returns true only if `actor` is a valid, untampered user whose role is
 * granted `action` on `resource` by the policy table. Every denial is logged
 * with the reason (invalid actor, tampered record, or policy).
 */
bool access_check(const user_t *actor, action_t action, resource_t resource);

/* Change `target`'s role. Requires access_check(actor, ACT_MANAGE_USERS,
 * RES_USERS) to pass. Returns true on success.
 */
bool assign_role(const user_t *actor, user_t *target, role_t new_role);

/* --- Audit log -------------------------------------------------------- */

/* Number of denials recorded since perm_init(). Useful for tests/demo. */
unsigned perm_denials(void);

#endif /* PERMISSIONS_H */
