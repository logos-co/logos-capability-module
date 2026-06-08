// Unit tests for CapabilityModuleImpl.
//
// requestModule() mints a UUID auth token, asks the target module to record it
// via informModuleToken_module(), and returns the token to the caller.
//
// Security contract (F-001, CWE-290): requestModule fails closed. It refuses to
// mint a token unless BOTH the requesting identity (fromModuleName) and the
// target (moduleName) are modules capability_module already knows about — i.e.
// have a token registered in the TokenManager (the host seeds one entry per
// loaded module via notifyCapabilityModule). An empty, unknown, or never-loaded
// name yields an empty result and no token is minted. This is defense-in-depth:
// it blocks spoofing a *non-loaded* identity, but cannot by itself stop a loaded
// module from presenting *another loaded module's* name — that needs the RPC
// layer to surface the verified caller token to this method.
//
// In mock mode, MockLogosObject::informModuleToken always returns true and
// records nothing, so the success-path tests focus on the externally-observable
// contract: the returned token's shape and uniqueness. Verifying the dispatch to
// informModuleToken_module would require extending the mock framework to record
// those calls.

#include <logos_test.h>
#include <logos_mock.h>

#include <QRegularExpression>
#include <QSet>
#include <QString>

#include "capability_module_impl.h"
#include "logos_api.h"

namespace {

// UUID without braces: 8-4-4-4-12 lowercase hex digits separated by hyphens.
const QRegularExpression kUuidRegex(
    QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));

// Seed a module's token so capability_module treats it as a known/loaded module.
void seedModule(const QString& name) {
    TokenManager::instance().saveToken(name, "seed-token-" + name);
}

}

// ── Success path: both caller and target are known modules ──────────────────

LOGOS_TEST(requestModule_returns_uuid_format_token) {
    LogosMockSetup mock;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.isEmpty());
    LOGOS_ASSERT(kUuidRegex.match(token).hasMatch());
}

LOGOS_TEST(requestModule_mints_unique_token_per_call) {
    LogosMockSetup mock;
    seedModule("requester");
    seedModule("target");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QSet<QString> tokens;
    for (int i = 0; i < 10; ++i) {
        tokens.insert(impl.requestModule("requester", "target"));
    }

    LOGOS_ASSERT_EQ(tokens.size(), 10);
}

LOGOS_TEST(requestModule_works_when_target_token_is_pre_seeded) {
    LogosMockSetup mock;
    // Seed both the caller and the target — exercises the getToken() path for
    // the target while satisfying the known-caller gate.
    seedModule("requester_module");
    TokenManager::instance().saveToken("target_module", "pre-seeded-token");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT(kUuidRegex.match(token).hasMatch());
}

// ── F-001 security regression: fail closed on unverified input ──────────────

LOGOS_TEST(requestModule_returns_empty_when_not_initialized) {
    LogosMockSetup mock;
    CapabilityModuleImpl impl;

    QString token = impl.requestModule("requester", "target");

    LOGOS_ASSERT_TRUE(token.isEmpty());
}

LOGOS_TEST(requestModule_rejects_empty_fromModuleName) {
    LogosMockSetup mock;
    seedModule("target_module");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("", "target_module");

    LOGOS_ASSERT_TRUE(token.isEmpty());
}

LOGOS_TEST(requestModule_rejects_unknown_fromModuleName) {
    LogosMockSetup mock;
    // Only the target is known; the requesting identity was never loaded.
    seedModule("target_module");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    // Spoofing a non-loaded identity must not mint a token.
    QString token = impl.requestModule("spoofed_module", "target_module");

    LOGOS_ASSERT_TRUE(token.isEmpty());
}

LOGOS_TEST(requestModule_rejects_unknown_target) {
    LogosMockSetup mock;
    // Only the caller is known; the target was never loaded.
    seedModule("requester_module");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "missing_target");

    LOGOS_ASSERT_TRUE(token.isEmpty());
}

LOGOS_TEST(requestModule_succeeds_for_known_caller_and_target) {
    LogosMockSetup mock;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.isEmpty());
    LOGOS_ASSERT(kUuidRegex.match(token).hasMatch());
}
