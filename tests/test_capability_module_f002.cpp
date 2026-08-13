// F-002 regression: identity spoofing in requestModule (CWE-290) — FIXED.
//
// Vulnerability (now closed): capability_module.requestModule trusted a
// caller-supplied `fromModuleName` string as the caller's identity. A loaded
// module holding its own capability_module token could pass a PEER's name and
// mint a capability under the peer's identity, defeating the access policy.
// See f_002_issue.md / f_002_walkthrough.md.
//
// Fix: requestModule now takes the caller's auth token as its first argument and
// VERIFIES the claimed `fromModuleName` against it —
//   constantTimeEquals(authToken, tokenManager->getToken(fromModuleName)).
// The host seeds capability_module's TokenManager with each module's own token,
// so only the real `fromModuleName` can present a matching token. A spoofer does
// not possess the victim's token and is rejected.
//
// These tests assert the SECURE post-fix behavior: the spoof is denied, the
// honest caller still succeeds. They are the inversion of the original exploit
// tests — each formerly-green exploit assertion is now a denial assertion.
//
// NOTE on `seedModule`: it stores TokenManager[name] = "token-for-<name>", which
// is exactly what getToken(<name>) returns inside requestModule. So presenting
// "token-for-X" is presenting X's genuine token; presenting it while claiming a
// different name is the spoof attempt.

#include <logos_test.h>
#include <logos_mock.h>

#include <QRegularExpression>
#include <QSet>
#include <QString>

#include "capability_module_plugin.h"
#include "logos_api.h"
#include "token_manager.h"

namespace {

// UUID without braces — capability_module mints tokens in this shape.
const QRegularExpression kUuidRegexF002(
    QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));

// Mark a module as loaded/known and record its genuine token. The value mirrors
// what the host stores in capability_module's TokenManager for a real module.
void seedLoadedModule(const QString& name) {
    TokenManager::instance().saveToken(name, "token-for-" + name);
}
QString tokenOf(const QString& name) { return "token-for-" + name; }

// The trusted core/capability_module channel token registerRestriction requires.
const QString kTrustedToken = QStringLiteral("token-for-capability_module");
void seedTrustedChannel() { seedLoadedModule("capability_module"); }

} // namespace

// ── F-002 core: spoofing a peer's identity is now denied ────────────────────
//
// evil_module is loaded and holds its OWN token. wallet_module is restricted to
// {payments_module}. evil tries to obtain a wallet capability by claiming to be
// payments_module — but it can only present its own token, which does not match
// payments_module's token, so the identity gate rejects it before policy.

LOGOS_TEST(f002_spoofed_caller_name_is_rejected_by_token_binding) {
    LogosMockSetup mock;
    seedTrustedChannel();
    seedLoadedModule("evil_module");
    seedLoadedModule("payments_module");
    seedLoadedModule("wallet_module");

    CapabilityModulePlugin plugin;
    LogosAPI api("capability_module");
    plugin.initLogos(&api);

    LOGOS_ASSERT_TRUE(plugin.registerRestriction(
        kTrustedToken, "wallet_module", QStringList{"payments_module"}));

    // THE EXPLOIT, NOW DENIED: evil presents its own token but claims to be
    // payments_module. getToken("payments_module") != evil's token -> rejected.
    const QString spoofed = plugin.requestModule(
        tokenOf("evil_module"), "payments_module", "wallet_module");
    LOGOS_ASSERT_TRUE(spoofed.isEmpty());

    // Control: evil asking as its true self is also denied (not on the allow-list),
    // but now via the policy gate after a successful identity check.
    const QString asSelf = plugin.requestModule(
        tokenOf("evil_module"), "evil_module", "wallet_module");
    LOGOS_ASSERT_TRUE(asSelf.isEmpty());

    // The legitimate caller still works: payments_module presents its real token
    // and claims its real name -> identity proven, policy allows -> token minted.
    const QString legit = plugin.requestModule(
        tokenOf("payments_module"), "payments_module", "wallet_module");
    LOGOS_ASSERT_FALSE(legit.isEmpty());
    LOGOS_ASSERT(kUuidRegexF002.match(legit).hasMatch());
}

// ── F-002: a valid token cannot be paired with someone else's name ──────────
//
// Even for an UNrestricted target, presenting a valid token under a mismatched
// name is rejected — identity must be proven regardless of policy. This pins the
// gate itself, independent of any restriction.

LOGOS_TEST(f002_valid_token_with_mismatched_name_is_rejected) {
    LogosMockSetup mock;
    seedLoadedModule("evil_module");
    seedLoadedModule("victim_module");
    seedLoadedModule("target_module");

    CapabilityModulePlugin plugin;
    LogosAPI api("capability_module");
    plugin.initLogos(&api);

    // evil holds a genuine (its own) token, but claims victim_module's name.
    const QString spoofed = plugin.requestModule(
        tokenOf("evil_module"), "victim_module", "target_module");
    LOGOS_ASSERT_TRUE(spoofed.isEmpty());

    // victim_module using its own token and name succeeds (no restriction here).
    const QString ok = plugin.requestModule(
        tokenOf("victim_module"), "victim_module", "target_module");
    LOGOS_ASSERT_FALSE(ok.isEmpty());
}

// ── F-002: an unmatched / empty token never proves identity ─────────────────

LOGOS_TEST(f002_empty_or_unknown_token_is_rejected) {
    LogosMockSetup mock;
    seedLoadedModule("requester_module");
    seedLoadedModule("target_module");

    CapabilityModulePlugin plugin;
    LogosAPI api("capability_module");
    plugin.initLogos(&api);

    // Empty token: cannot prove identity.
    LOGOS_ASSERT_TRUE(
        plugin.requestModule("", "requester_module", "target_module").isEmpty());

    // Non-empty but wrong token (not requester_module's): rejected.
    LOGOS_ASSERT_TRUE(
        plugin.requestModule("not-the-right-token", "requester_module", "target_module").isEmpty());

    // Correct token + name: succeeds, confirming the negatives above fail for the
    // right reason (identity check) and not some unrelated gate.
    LOGOS_ASSERT_FALSE(
        plugin.requestModule(tokenOf("requester_module"), "requester_module", "target_module").isEmpty());
}

// ── Out of scope (separate issue): fail-open default ────────────────────────
//
// With NO policy registered, the access-policy gate is skipped entirely (the
// documented fail-OPEN default, TODO at capability_module_plugin.cpp:93-98). This
// is a SEPARATE weakness from F-002 identity spoofing and was intentionally left
// unchanged by this fix (see plan / user scope decision). After the identity fix,
// a module presenting its OWN genuine token still reaches any unrestricted target.
// This test documents that remaining, intentional behavior — flip it when/if the
// fail-open default is changed to deny-by-default.

LOGOS_TEST(f002_failopen_default_still_allows_unrestricted_target_OUT_OF_SCOPE) {
    LogosMockSetup mock;
    seedLoadedModule("some_module");
    seedLoadedModule("open_target");

    CapabilityModulePlugin plugin;
    LogosAPI api("capability_module");
    plugin.initLogos(&api);

    // No registerRestriction -> fail open. some_module proves its own identity and
    // reaches open_target. (This is NOT the spoofing bug; it's the rollout TODO.)
    const QString tok = plugin.requestModule(
        tokenOf("some_module"), "some_module", "open_target");
    LOGOS_ASSERT_FALSE(tok.isEmpty());
}
