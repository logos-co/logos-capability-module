// Unit tests for CapabilityModuleImpl.
//
// capability_module is a universal module: a plain, Qt-free C++ class deriving
// LogosModuleContext, whose public methods ARE its API (the builder generates
// the plugin glue). So these tests construct the impl class directly — there is
// no plugin object and no initLogos step to perform.
//
// requestModule() mints a UUID auth token, pushes it to the target module, and
// returns it to the caller.
//
// ── What is REAL here and what is not ────────────────────────────────────────
//
// Nothing is faked at the lp_* / host-services layer. Every test drives the
// genuine article:
//
//   * the host-services grant     — lp_grant_host_services(), the same public C
//                                   ABI the host calls; the gates inside
//                                   lp_token_keys / lp_inform_module_token_to
//                                   really fire
//   * the token registry          — lp_token_save() into this image's real
//                                   TokenManager, read back through the real
//                                   logos::host::tokenKeys()/tokenFor()
//   * the client                  — a real lp_client_create()
//   * the token push              — a real logos::host::informModuleTokenTo(),
//                                   which really goes LogosAPIClient ->
//                                   LogosAPIConsumer::informModuleToken_module
//                                   -> acquire "<target>__handshake" ->
//                                   LogosObject::informModuleToken
//
// Only the TRANSPORT is substituted, and only by switching the process mode.
// LogosMockSetup puts the SDK in LogosMode::Mock, where
// MockTransportConnection::requestObject vends a MockLogosObject for any name
// and MockLogosObject::informModuleToken returns true. That is what lets the
// success-path tests run all nine steps of requestModule in-process, with no
// seam in the impl and no production call site changed — and it is why the
// tests take ~0 ms rather than timing out on kTokenPushTimeoutMs.
//
// The consequence: the mock accepts every push and records nothing, so no test
// here can assert WHICH module was told or WHICH token it received. Verifying
// the argument order that capability_module_impl.cpp:127-133 warns about would
// need a recording endpoint (local mode + a real ModuleProxy), which drags Qt
// types into this file; the impl is deliberately Qt-free and so is this suite.
// That gap is unchanged from the pre-migration tests.
//
// ── Security contract (F-001, CWE-290) ───────────────────────────────────────
//
// requestModule fails closed. Identity is logos::currentCaller() (the document
// the host pushed for this dispatch), not fromModuleName. Direct unit tests
// must wrap calls with AsModule / AsHost — production RPC glue does that via
// logos_module_set_call_caller. An unnamed dispatch, an empty target, a
// never-loaded TARGET, or a policy miss yields an empty result and no token
// is minted. Spoofing fromModuleName cannot impersonate another loaded module.
//
// Under `universal` there is a second, stronger fail-closed precondition the
// old Qt shape could not express at all: the host-services grant. Reading the
// token registry now requires "token_registry" and pushing a token requires
// "token_delivery"; ungranted, requestModule refuses EVERY request. Both are
// covered below.
//
// ── Test isolation ───────────────────────────────────────────────────────────
//
// The token store and the host-services grant are both PROCESS-GLOBAL, and
// lp_grant_host_services REPLACES the grant rather than adding to it, so state
// leaking between tests would make results order-dependent. CapabilityFixture
// re-establishes BOTH from scratch on every construction — LogosMockSetup's
// constructor clears the token store, and the grant is replaced wholesale — so
// no test can inherit anything from the one before it. Its destructor also
// clears the grant, so a future test that forgets the fixture fails closed
// instead of silently borrowing a neighbour's privileges.

#include <logos_test.h>
#include <logos_mock.h>      // LogosMockSetup: LogosMode::Mock + token-store reset
#include <logos_protocol.h>  // lp_grant_host_services, lp_token_save, lp_set_mode, LP_OK
#include <logos_caller.h>    // logos::detail::setCallCaller — stand-in for RPC glue

#include "capability_module_impl.h"

#include <cstddef>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace {

// The grant capability_module declares in metadata.json#host_services.
constexpr const char* kAllHostServices = R"(["token_registry","token_delivery"])";
// Registry only: enough to verify a caller, NOT enough to deliver the token.
constexpr const char* kRegistryOnly    = R"(["token_registry"])";
constexpr const char* kNoHostServices  = "[]";

// One guard per test; construct it FIRST, before any seeding.
//
// Order matters and is enforced by declaration order: m_mock is built before
// the grant, and LogosMockSetup's constructor calls clearAllTokens(). Seeding
// before the fixture would therefore be silently wiped.
class CapabilityFixture {
public:
    explicit CapabilityFixture(const char* servicesJson = kAllHostServices)
        : m_grantRc(lp_grant_host_services(servicesJson)) {}

    ~CapabilityFixture() { lp_grant_host_services(kNoHostServices); }

    CapabilityFixture(const CapabilityFixture&) = delete;
    CapabilityFixture& operator=(const CapabilityFixture&) = delete;

    int grantRc() const { return m_grantRc; }

private:
    LogosMockSetup m_mock;  // must be declared first: it clears the token store
    int m_grantRc;
};

// Seed a module's token so capability_module treats it as a known/loaded
// module — the test-side stand-in for the host seeding one entry per module it
// loads. Goes through the real C ABI into the real image token store.
void seedModule(const std::string& name) {
    lp_token_save(name.c_str(), ("seed-token-" + name).c_str());
}

// The trusted core/capability_module auth token. registerRestriction requires
// it; only core holds it in production. In tests it is whatever seedModule
// stored for "capability_module".
const std::string kTrustedToken = "seed-token-capability_module";

// Seed the trusted channel so registerRestriction calls authenticate. Call in
// any test that registers a restriction.
void seedTrustedChannel() {
    seedModule("capability_module");
}

// Production requestModule runs under logos_module_set_call_caller. These
// tests construct the impl directly, so they push the same document the
// generated glue would.
class AsModule {
public:
    explicit AsModule(const std::string& name)
        : m_json(std::string(R"({"kind":"module","name":")") + name + "\"}")
    {
        logos::detail::setCallCaller(m_json.c_str());
    }
    ~AsModule() { logos::detail::setCallCaller(nullptr); }
    AsModule(const AsModule&) = delete;
    AsModule& operator=(const AsModule&) = delete;
private:
    std::string m_json;
};

class AsHost {
public:
    AsHost() { logos::detail::setCallCaller(R"({"kind":"host"})"); }
    ~AsHost() { logos::detail::setCallCaller(nullptr); }
    AsHost(const AsHost&) = delete;
    AsHost& operator=(const AsHost&) = delete;
};

// UUID without braces: 8-4-4-4-12 lowercase hex digits separated by hyphens.
bool isUuid(const std::string& s) {
    static const std::regex re(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    return std::regex_match(s, re);
}

}  // namespace

// ── Success path: both caller and target are known modules ──────────────────

LOGOS_TEST(requestModule_returns_uuid_format_token) {
    CapabilityFixture fixture;
    LOGOS_ASSERT_EQ(fixture.grantRc(), LP_OK);
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_mints_unique_token_per_call) {
    CapabilityFixture fixture;
    seedModule("requester");
    seedModule("target");

    CapabilityModuleImpl impl;
    AsModule caller("requester");

    std::set<std::string> tokens;
    for (int i = 0; i < 10; ++i) {
        tokens.insert(impl.requestModule("requester", "target"));
    }

    // Also the sharpest liveness detector in the suite: if the push had failed,
    // all ten would be "" and the set would collapse to size 1.
    LOGOS_ASSERT_EQ(tokens.size(), std::size_t(10));
}

LOGOS_TEST(requestModule_works_when_target_token_is_pre_seeded) {
    CapabilityFixture fixture;
    // Seed both the caller and the target — exercises the tokenFor() path for
    // the target. The literal value differs from seedModule's to show nothing
    // reads it.
    seedModule("requester_module");
    lp_token_save("target_module", "pre-seeded-token");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT(isUuid(token));
}

// ── F-001 security regression: fail closed on unverified input ──────────────

// Replaces the old `requestModule_returns_empty_when_not_initialized`. The
// universal shape has no init step and no injected LogosAPI, so there is no
// "not initialized" state to test; the nearest real fail-closed precondition —
// and a stronger one — is the host-services grant this module now depends on.
//
// Note this asserts the CONTRACT, not one code path: with no grant,
// tokenKeys() also comes back empty, so the known-caller gate would refuse
// these inputs even if the explicit ungranted() check were deleted.
LOGOS_TEST(requestModule_returns_empty_when_host_services_ungranted) {
    CapabilityFixture fixture(kNoHostServices);
    LOGOS_ASSERT_EQ(fixture.grantRc(), LP_OK);
    seedModule("requester");
    seedModule("target");

    CapabilityModuleImpl impl;
    AsModule caller("requester");

    // Both names are known and the pair is unrestricted: the ONLY thing
    // refusing this request is the missing grant.
    const std::string token = impl.requestModule("requester", "target");

    LOGOS_ASSERT_TRUE(token.empty());
}

// The second half of the grant, which nothing else covers: an image allowed to
// VERIFY a caller but not to DELIVER a token must still refuse, rather than
// hand back a token the target was never told about.
LOGOS_TEST(requestModule_returns_empty_when_token_delivery_ungranted) {
    CapabilityFixture fixture(kRegistryOnly);
    LOGOS_ASSERT_EQ(fixture.grantRc(), LP_OK);
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    // Clears gates 1-5 and mints a token; the push then comes back
    // LP_ERR_UNSUPPORTED, so the minted token is dropped on the floor.
    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
}

// Direct construction has no logos_module_set_call_caller push. With an
// empty leftover ABI and no caller, refuse. A filled fromModuleName is the
// old-host fallback and is covered below.
LOGOS_TEST(requestModule_rejects_unnamed_caller) {
    CapabilityFixture fixture;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;

    const std::string token = impl.requestModule("", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_falls_back_to_fromModuleName_without_caller) {
    // Old logoscore / mock / doctest: no caller document on the dispatch,
    // only the leftover ABI. Same grant as master before this PR.
    CapabilityFixture fixture;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_treats_host_as_core) {
    CapabilityFixture fixture;
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsHost host;

    const std::string token = impl.requestModule("ignored_leftover", "target_module");

    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_ignores_leftover_fromModuleName) {
    CapabilityFixture fixture;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    // Empty leftover ABI still mints for the token-bound caller.
    const std::string token = impl.requestModule("", "target_module");

    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_rejects_empty_targetModuleName) {
    CapabilityFixture fixture;
    seedModule("requester_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_rejects_unknown_target) {
    CapabilityFixture fixture;
    seedModule("requester_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "missing_target");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_succeeds_for_known_caller_and_target) {
    // The positive control for this section. Without it every assertion above
    // would still pass against a requestModule that returned "" unconditionally
    // — or against a harness that had quietly stopped working.
    CapabilityFixture fixture;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isUuid(token));
}

// The remaining refusal in requestModule: the push reached a real transport and
// genuinely failed, as opposed to being refused for want of a grant. Mock mode
// cannot produce it — MockLogosObject accepts everything — so this one test
// runs in LogosMode::Local with nothing published in the PluginRegistry.
// LocalTransportConnection::requestObject then misses on both the handshake
// surface and the business object and returns immediately, so this costs no
// wall-clock time despite exercising the failure arm.
LOGOS_TEST(requestModule_returns_empty_when_target_is_unreachable) {
    CapabilityFixture fixture;
    LOGOS_ASSERT_EQ(lp_set_mode("local"), LP_OK);  // fixture's dtor restores the mode
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
}

// ── Access-policy enforcement (registerRestriction + requestModule) ─────────
//
// Core parses the access policy and calls registerRestriction(target,
// allowedCallers) for each restricted target. requestModule then refuses to
// mint a token when a restricted target's allowed-caller set does not include
// the requester — the denied caller never gets credentials, so it can never
// call the target. A target with NO registered restriction stays unrestricted.

LOGOS_TEST(registerRestriction_rejects_empty_target) {
    CapabilityFixture fixture;
    seedTrustedChannel();

    CapabilityModuleImpl impl;

    // Passes the trusted-token gate, then is refused by the empty-target gate —
    // which pins the gate ORDER: trust is checked before argument validity.
    LOGOS_ASSERT_FALSE(impl.registerRestriction(kTrustedToken, "", {"caller"}));
}

LOGOS_TEST(registerRestriction_rejects_untrusted_caller_token) {
    // A loaded module can reach this method (the generic authorization that
    // fronts it accepts any issued token), so the explicit trusted-token gate
    // is the real defense: a peer presenting its own token must NOT be able to
    // register a restriction.
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("malicious_module");
    seedModule("package_manager");

    CapabilityModuleImpl impl;

    // malicious_module tries to grant itself access using its OWN token.
    const bool ok = impl.registerRestriction(
        "seed-token-malicious_module", "package_manager", {"malicious_module"});
    LOGOS_ASSERT_FALSE(ok);

    // And an empty token is rejected too.
    LOGOS_ASSERT_FALSE(impl.registerRestriction(
        "", "package_manager", {"malicious_module"}));
}

LOGOS_TEST(requestModule_allows_listed_caller_for_restricted_target) {
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("package_manager_ui");
    seedModule("package_manager");

    CapabilityModuleImpl impl;

    LOGOS_ASSERT_TRUE(impl.registerRestriction(
        kTrustedToken, "package_manager", {"package_manager_ui"}));

    AsModule caller("package_manager_ui");
    const std::string token = impl.requestModule("package_manager_ui", "package_manager");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_denies_unlisted_caller_for_restricted_target) {
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("some_other_module");
    seedModule("package_manager");

    CapabilityModuleImpl impl;

    impl.registerRestriction(kTrustedToken, "package_manager", {"package_manager_ui"});

    // some_other_module is a named, loaded module but is not in
    // package_manager's allowed-caller set — must be denied.
    AsModule caller("some_other_module");
    const std::string token = impl.requestModule("some_other_module", "package_manager");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_allows_any_caller_for_unrestricted_target) {
    // Pins the deliberate fail-OPEN policy decision (see the
    // TODO(access-policy) in capability_module_impl.cpp). Nothing else does:
    // flipping to deny-by-default must turn THIS test red.
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("some_module");
    seedModule("restricted_target");
    seedModule("open_target");

    CapabilityModuleImpl impl;

    // Restrict only restricted_target; open_target has no restriction.
    impl.registerRestriction(kTrustedToken, "restricted_target", {"allowed_caller"});

    AsModule caller("some_module");
    const std::string token = impl.requestModule("some_module", "open_target");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_allows_all_when_no_restriction_registered) {
    // Back-compat: with no policy pushed, every known caller/target pair works.
    CapabilityFixture fixture;
    seedModule("requester_module");
    seedModule("target_module");

    CapabilityModuleImpl impl;
    AsModule caller("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.empty());
}

LOGOS_TEST(registerRestriction_overwrites_previous_for_same_target) {
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("old_caller");
    seedModule("new_caller");
    seedModule("target_module");

    CapabilityModuleImpl impl;

    impl.registerRestriction(kTrustedToken, "target_module", {"old_caller"});
    // Re-register (as core does each boot) with a different allowed set.
    impl.registerRestriction(kTrustedToken, "target_module", {"new_caller"});

    // old_caller is no longer allowed; new_caller is. The second assertion is
    // what distinguishes "overwritten" from "registerRestriction broke the
    // target for everyone".
    {
        AsModule oldCaller("old_caller");
        LOGOS_ASSERT_TRUE(impl.requestModule("old_caller", "target_module").empty());
    }
    {
        AsModule newCaller("new_caller");
        LOGOS_ASSERT_FALSE(impl.requestModule("new_caller", "target_module").empty());
    }
}

LOGOS_TEST(requestModule_denies_spoofed_fromModuleName) {
    CapabilityFixture fixture;
    seedTrustedChannel();
    seedModule("package_manager_ui");
    seedModule("package_manager");
    seedModule("malicious_module");

    CapabilityModuleImpl impl;

    LOGOS_ASSERT_TRUE(impl.registerRestriction(
        kTrustedToken, "package_manager", {"package_manager_ui"}));

    // Token-bound caller is malicious_module; leftover ABI claims the UI.
    AsModule caller("malicious_module");
    const std::string token = impl.requestModule("package_manager_ui", "package_manager");

    LOGOS_ASSERT_TRUE(token.empty());
}
