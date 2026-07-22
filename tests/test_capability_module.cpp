// Unit tests for CapabilityModuleImpl.
//
// capability_module is a Qt-free UNIVERSAL module: its logic lives in
// CapabilityModuleImpl (std::string), and it reaches the host's token store +
// arbitrary-module inform through the LogosTokenManagerContext bridge. That
// makes it directly unit-testable — no LogosAPI / mock transport needed: we
// inject std::function stubs via _logosCoreSetTokenBridge_ and drive
// requestModule / registerRestriction.
//
// requestModule() mints an opaque token, asks the target to record it via the
// inform bridge, and returns the token to the caller.
//
// Security contract (F-001, CWE-290): requestModule fails closed. It refuses to
// mint a token unless BOTH the requesting identity (fromModuleName) and the
// target (moduleName) are modules capability_module already knows about — i.e.
// have a token in the host store (getToken returns non-empty). An empty,
// unknown, or never-loaded name yields an empty result and no token is minted.

#include <logos_test.h>

#include <set>
#include <string>
#include <vector>

#include "capability_module_impl.h"

namespace {

// True iff `s` is exactly 32 lowercase hex characters (the mintToken() shape).
bool isHex32(const std::string& s) {
    if (s.size() != 32) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// A CapabilityModuleImpl wired to in-memory stubs. `seed(name)` marks a module
// as known (getToken returns a token for it); inform always succeeds, matching
// the old mock's MockLogosObject::informModuleToken.
struct Fixture {
    std::set<std::string> known;
    CapabilityModuleImpl impl;

    Fixture() {
        impl._logosCoreSetTokenBridge_(
            [this](const std::string& name) -> std::string {
                return known.count(name) ? ("seed-token-" + name) : std::string();
            },
            [](const std::string&, const std::string&,
               const std::string&, const std::string&) -> bool {
                return true;
            });
    }

    void seed(const std::string& name) { known.insert(name); }
};

// The trusted core/capability_module auth token registerRestriction requires —
// whatever the stub returns for "capability_module" once seeded.
const std::string kTrustedToken = "seed-token-capability_module";

} // namespace

// ── Success path: both caller and target are known modules ──────────────────

LOGOS_TEST(requestModule_returns_hex_token) {
    Fixture f;
    f.seed("requester_module");
    f.seed("target_module");

    const std::string token = f.impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isHex32(token));
}

LOGOS_TEST(requestModule_mints_unique_token_per_call) {
    Fixture f;
    f.seed("requester");
    f.seed("target");

    std::set<std::string> tokens;
    for (int i = 0; i < 10; ++i)
        tokens.insert(f.impl.requestModule("requester", "target"));

    LOGOS_ASSERT_EQ(static_cast<int>(tokens.size()), 10);
}

// ── F-001 security regression: fail closed on unverified input ──────────────

LOGOS_TEST(requestModule_returns_empty_when_bridge_unwired) {
    // No _logosCoreSetTokenBridge_ call: getToken no-ops to "" for every name,
    // so both the known-caller and known-target gates fail closed.
    CapabilityModuleImpl impl;
    const std::string token = impl.requestModule("requester", "target");
    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_rejects_empty_fromModuleName) {
    Fixture f;
    f.seed("target_module");
    LOGOS_ASSERT_TRUE(f.impl.requestModule("", "target_module").empty());
}

LOGOS_TEST(requestModule_rejects_unknown_fromModuleName) {
    Fixture f;
    // Only the target is known; the requesting identity was never loaded.
    f.seed("target_module");
    // Spoofing a non-loaded identity must not mint a token.
    LOGOS_ASSERT_TRUE(f.impl.requestModule("spoofed_module", "target_module").empty());
}

LOGOS_TEST(requestModule_rejects_unknown_target) {
    Fixture f;
    // Only the caller is known; the target was never loaded.
    f.seed("requester_module");
    LOGOS_ASSERT_TRUE(f.impl.requestModule("requester_module", "missing_target").empty());
}

// ── Access-policy enforcement (registerRestriction + requestModule) ─────────

LOGOS_TEST(registerRestriction_rejects_empty_target) {
    Fixture f;
    f.seed("capability_module");
    LOGOS_ASSERT_FALSE(f.impl.registerRestriction(kTrustedToken, "", {"caller"}));
}

LOGOS_TEST(registerRestriction_rejects_untrusted_caller_token) {
    Fixture f;
    f.seed("capability_module");
    f.seed("malicious_module");
    f.seed("package_manager");

    // malicious_module tries to grant itself access using its OWN token.
    LOGOS_ASSERT_FALSE(f.impl.registerRestriction(
        "seed-token-malicious_module", "package_manager", {"malicious_module"}));
    // And an empty token is rejected too.
    LOGOS_ASSERT_FALSE(f.impl.registerRestriction(
        "", "package_manager", {"malicious_module"}));
}

LOGOS_TEST(requestModule_allows_listed_caller_for_restricted_target) {
    Fixture f;
    f.seed("capability_module");
    f.seed("package_manager_ui");
    f.seed("package_manager");

    LOGOS_ASSERT_TRUE(f.impl.registerRestriction(
        kTrustedToken, "package_manager", {"package_manager_ui"}));

    const std::string token = f.impl.requestModule("package_manager_ui", "package_manager");
    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isHex32(token));
}

LOGOS_TEST(requestModule_denies_unlisted_caller_for_restricted_target) {
    Fixture f;
    f.seed("capability_module");
    f.seed("other_module");
    f.seed("package_manager");

    // Restrict package_manager to package_manager_ui only.
    LOGOS_ASSERT_TRUE(f.impl.registerRestriction(
        kTrustedToken, "package_manager", {"package_manager_ui"}));

    // A known-but-unlisted caller is denied a token for the restricted target.
    LOGOS_ASSERT_TRUE(f.impl.requestModule("other_module", "package_manager").empty());
}
