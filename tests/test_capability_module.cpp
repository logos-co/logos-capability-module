// Unit tests for CapabilityModuleImpl.
//
// requestModule() mints a UUID auth token, asks the target module to record
// it via informModuleToken_module(), and returns the token to the caller.
// In mock mode, MockLogosObject::informModuleToken always returns true and
// records nothing, so these tests focus on the externally-observable
// contract: the returned token's shape, uniqueness, and the not-initialized
// guard. Verifying the dispatch to informModuleToken_module would require
// extending the mock framework to record those calls.

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

}

LOGOS_TEST(requestModule_returns_uuid_format_token) {
    LogosMockSetup mock;
    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.isEmpty());
    LOGOS_ASSERT(kUuidRegex.match(token).hasMatch());
}

LOGOS_TEST(requestModule_mints_unique_token_per_call) {
    LogosMockSetup mock;
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
    // Seed a token for the target module — exercises the getToken() path.
    TokenManager::instance().saveToken("target_module", "pre-seeded-token");

    CapabilityModuleImpl impl;
    LogosAPI api("capability_module");
    impl.init(&api);

    QString token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT(kUuidRegex.match(token).hasMatch());
}

LOGOS_TEST(requestModule_returns_empty_when_not_initialized) {
    LogosMockSetup mock;
    CapabilityModuleImpl impl;

    QString token = impl.requestModule("requester", "target");

    LOGOS_ASSERT_TRUE(token.isEmpty());
}
