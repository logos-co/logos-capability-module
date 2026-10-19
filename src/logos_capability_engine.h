#ifndef LOGOS_CAPABILITY_ENGINE_H
#define LOGOS_CAPABILITY_ENGINE_H

/* The runtime engine's private interface to the capability authority. It is not
 * part of capability_module's dispatch surface: the engine looks it up by symbol
 * in the image it loaded in-process. Returned strings are freed with string_free;
 * every entry is thread-safe and never calls back into the engine. */

#ifdef __cplusplus
extern "C" {
#endif

#define LOGOS_CAPABILITY_ENGINE_VERSION 1
#define LOGOS_CAPABILITY_ENGINE_SYMBOL "logos_module_capability_engine_v1"

typedef struct logos_capability_engine_v1 {
    unsigned size;    /* sizeof(logos_capability_engine_v1) as the authority built it */
    unsigned version; /* LOGOS_CAPABILITY_ENGINE_VERSION */

    /* Admits `name` as "module", "shell" or "presentation" and mints its
     * credential; NULL when refused. `*generation` names this admission. */
    char* (*admit)(const char* name, const char* kind, unsigned long long* generation);
    /* Ends admission `generation` of `name`: its credential and the pair tokens it
     * holds are revoked. 0, or -1 for an unknown or stale generation. */
    int (*retire)(const char* name, unsigned long long generation);
    /* {"kind":"module","name":...} for a presented credential; NULL for anything else. */
    char* (*resolve_caller)(const char* token, const char* transport);
    /* An admitted identity's credential, for the engine's own calls to it. */
    char* (*credential_for)(const char* name);
    /* A token letting operator `op` call `target`, which learns it as "@op:<op>". */
    char* (*grant_operator_pair)(const char* op, const char* target);
    /* Replaces the access restrictions, {"<target>":["<caller>",...]}; a target
     * absent is unrestricted. 0, or -1 for a malformed document. */
    int (*set_restrictions)(const char* restrictions_json);
    void (*string_free)(char* value);
} logos_capability_engine_v1;

typedef const logos_capability_engine_v1* (*logos_module_capability_engine_v1_fn)(void);

#ifdef __cplusplus
}
#endif

#endif /* LOGOS_CAPABILITY_ENGINE_H */
