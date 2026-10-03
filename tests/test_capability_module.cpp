// Unit tests for CapabilityModuleImpl.
//
// capability_module is a universal module: a plain, Qt-free C++ class deriving
// LogosModuleContext, whose public methods ARE its API (the builder generates
// the plugin glue). So these tests construct the impl class directly.
//
// requestModule() mints a token for an admitted (caller, target) pair, pushes
// it to the target with the target's own credential, and returns it. The
// runtime admits every module through the engine interface, and so do these
// tests: CapabilityFixture::admit goes through logos_module_capability_engine_v1,
// the same table liblogos calls.
//
// ── What is REAL here and what is not ────────────────────────────────────────
//
// The grant (lp_grant_host_services), the client (lp_client_create) and the push
// (logos::host::informModuleTokenTo) are the real ones. Only the TRANSPORT is
// substituted: LogosMockSetup puts the SDK in LogosMode::Mock, where every push
// is accepted, so no test here can assert WHICH module was told. Revocations are
// recorded rather than dialled (CapabilityAuthority::setRevocationPush).
//
// ── Security contract (F-001, CWE-290) ───────────────────────────────────────
//
// requestModule fails closed. Identity is logos::currentCaller(), not
// fromModuleName; tests set it with logos::CallCaller (logos_test.h), as the RPC
// glue does with logos_module_set_call_caller. An unnamed dispatch, an empty
// target, a target the runtime never admitted, a policy miss, or a push that
// cannot be made yields an empty result, and no pair is left on record.

#include <logos_test.h>
#include <logos_mock.h>      // LogosMockSetup: LogosMode::Mock + token-store reset
#include <logos_protocol.h>  // lp_grant_host_services, lp_token_save, lp_set_mode, LP_OK

#include "capability_authority.h"
#include "capability_module_impl.h"
#include "logos_capability_engine.h"

#include <mutex>
#include <regex>
#include <string>
#include <utility>
#include <vector>

extern "C" const logos_capability_engine_v1* logos_module_capability_engine_v1();

namespace {

constexpr const char* kTokenDelivery   = R"(["token_delivery"])";
constexpr const char* kNoHostServices  = "[]";

const logos_capability_engine_v1& engine()
{
    return *logos_module_capability_engine_v1();
}

std::mutex g_revokedMutex;
std::vector<CapabilityAuthority::Revocation> g_revoked;

std::vector<CapabilityAuthority::Revocation> revoked()
{
    CapabilityAuthority::instance().drainRevocations();
    std::lock_guard<std::mutex> lock(g_revokedMutex);
    return g_revoked;
}

std::string digestOf(const std::string& token)
{
    char* digest = lp_token_digest(token.c_str());
    std::string value = digest ? digest : "";
    lp_string_free(digest);
    return value;
}

// One guard per test. It sets the transport and the grant, admits what the test
// asks for, and on the way out retires every admission and clears the policy,
// so no test inherits a neighbour's identities, pairs or privileges.
class CapabilityFixture {
public:
    explicit CapabilityFixture(const char* servicesJson = kTokenDelivery)
        : m_grantRc(lp_grant_host_services(servicesJson))
    {
        CapabilityAuthority::instance().setRevocationPush(
            [](const CapabilityAuthority::Revocation& revocation, const std::string&) {
                std::lock_guard<std::mutex> lock(g_revokedMutex);
                g_revoked.push_back(revocation);
                return LP_OK;
            });
    }

    ~CapabilityFixture()
    {
        for (const auto& [name, generation] : m_admitted)
            engine().retire(name.c_str(), generation);
        engine().set_restrictions("{}");
        CapabilityAuthority::instance().drainRevocations();
        CapabilityAuthority::instance().setRevocationPush({});
        {
            std::lock_guard<std::mutex> lock(g_revokedMutex);
            g_revoked.clear();
        }
        lp_grant_host_services(kNoHostServices);
    }

    CapabilityFixture(const CapabilityFixture&) = delete;
    CapabilityFixture& operator=(const CapabilityFixture&) = delete;

    int grantRc() const { return m_grantRc; }

    // Admits `name` as the runtime does when it loads a module.
    void admit(const std::string& name, const char* kind = "module")
    {
        unsigned long long generation = 0;
        char* credential = engine().admit(name.c_str(), kind, &generation);
        engine().string_free(credential);
        m_admitted.emplace_back(name, generation);
    }

    // Retires `name` as the runtime does when it unloads it.
    void retire(const std::string& name)
    {
        for (auto it = m_admitted.begin(); it != m_admitted.end(); ++it) {
            if (it->first != name) continue;
            engine().retire(name.c_str(), it->second);
            m_admitted.erase(it);
            return;
        }
    }

private:
    LogosMockSetup m_mock;  // declared first: it clears the token store
    int m_grantRc;
    std::vector<std::pair<std::string, unsigned long long>> m_admitted;
};

// UUID without braces: 8-4-4-4-12 lowercase hex digits separated by hyphens.
bool isUuid(const std::string& s) {
    static const std::regex re(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    return std::regex_match(s, re);
}

bool pairOnRecord(const std::string& caller, const std::string& target)
{
    return !CapabilityAuthority::instance().pairToken(caller, target).empty();
}

}  // namespace

// ── Success path: an admitted caller asks for an admitted target ────────────

LOGOS_TEST(requestModule_returns_uuid_format_token) {
    CapabilityFixture fixture;
    LOGOS_ASSERT_EQ(fixture.grantRc(), LP_OK);
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT(isUuid(token));
}

LOGOS_TEST(requestModule_succeeds_for_admitted_caller_and_target) {
    // The positive control. Without it every refusal below would still pass
    // against a requestModule that returned "" unconditionally.
    CapabilityFixture fixture;
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT(isUuid(token));
    LOGOS_ASSERT(pairOnRecord("requester_module", "target_module"));
}

LOGOS_TEST(requestModule_treats_host_as_core) {
    CapabilityFixture fixture;
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto host = logos::CallCaller::host();

    const std::string token = impl.requestModule("ignored_leftover", "target_module");

    LOGOS_ASSERT(isUuid(token));
    LOGOS_ASSERT(pairOnRecord("core", "target_module"));
}

LOGOS_TEST(requestModule_ignores_leftover_fromModuleName) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    // Empty leftover ABI still mints for the token-bound caller.
    const std::string token = impl.requestModule("", "target_module");

    LOGOS_ASSERT(isUuid(token));
}

// ── F-001 security regression: fail closed on unverified input ──────────────

// Direct construction has no logos_module_set_call_caller push. An unnamed
// dispatch must refuse even when fromModuleName names an admitted module.
LOGOS_TEST(requestModule_rejects_unnamed_caller) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_rejects_empty_targetModuleName) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "");

    LOGOS_ASSERT_TRUE(token.empty());
}

LOGOS_TEST(requestModule_rejects_unknown_target) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "missing_target");

    LOGOS_ASSERT_TRUE(token.empty());
}

// The registry is gone: a token in this image's store, which is what the
// runtime used to push for every module it loaded, no longer makes a target.
LOGOS_TEST(requestModule_refuses_a_target_the_runtime_never_admitted) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");
    lp_token_save("stored_target", "a-token-core-once-pushed");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "stored_target");

    LOGOS_ASSERT_TRUE(token.empty());
    LOGOS_ASSERT_FALSE(pairOnRecord("requester_module", "stored_target"));
}

// No token_delivery: the push is refused at the gate, so the minted token is
// dropped and the pair it was recorded under is forgotten.
LOGOS_TEST(requestModule_returns_empty_when_token_delivery_ungranted) {
    CapabilityFixture fixture(kNoHostServices);
    LOGOS_ASSERT_EQ(fixture.grantRc(), LP_OK);
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
    LOGOS_ASSERT_FALSE(pairOnRecord("requester_module", "target_module"));
}

// The push reached a real transport and genuinely failed. Mock mode cannot
// produce it — MockLogosObject accepts everything — so this one test runs in
// LogosMode::Local with nothing published, which misses immediately.
LOGOS_TEST(requestModule_returns_empty_when_target_is_unreachable) {
    CapabilityFixture fixture;
    LOGOS_ASSERT_EQ(lp_set_mode("local"), LP_OK);  // LogosMockSetup restores the mode
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");

    const std::string token = impl.requestModule("requester_module", "target_module");

    LOGOS_ASSERT_TRUE(token.empty());
    LOGOS_ASSERT_FALSE(pairOnRecord("requester_module", "target_module"));
}

// ── Retirement ──────────────────────────────────────────────────────────────

// What others hold for a retired module died with it: nothing is pushed, and a
// re-admitted target gets a new pair token.
LOGOS_TEST(retiring_the_target_forgets_the_pair_without_a_push) {
    CapabilityFixture fixture;
    fixture.admit("requester_module");
    fixture.admit("target_module");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("requester_module");
    const std::string first = impl.requestModule("", "target_module");
    LOGOS_ASSERT(isUuid(first));

    fixture.retire("target_module");
    LOGOS_ASSERT_FALSE(pairOnRecord("requester_module", "target_module"));
    LOGOS_ASSERT(revoked().empty());

    fixture.admit("target_module");
    const std::string second = impl.requestModule("", "target_module");
    LOGOS_ASSERT(isUuid(second));
    LOGOS_ASSERT_NE(second, first);
}

// ── Access policy, from the runtime through set_restrictions ────────────────

LOGOS_TEST(requestModule_allows_any_caller_for_unrestricted_target) {
    // Pins the deliberate fail-OPEN policy decision (see the TODO(access-policy)
    // in capability_module_impl.cpp). Flipping to deny-by-default must turn
    // THIS test red.
    CapabilityFixture fixture;
    fixture.admit("some_module");
    fixture.admit("restricted_target");
    fixture.admit("open_target");
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"restricted_target":["allowed_caller"]})"), 0);

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("some_module");

    LOGOS_ASSERT(isUuid(impl.requestModule("some_module", "open_target")));
    LOGOS_ASSERT_TRUE(impl.requestModule("some_module", "restricted_target").empty());
}

// A new policy replaces the old one whole, and a pair it now denies is revoked
// at the target rather than left working until its next request.
LOGOS_TEST(a_new_policy_revokes_the_pair_it_denies) {
    CapabilityFixture fixture;
    fixture.admit("old_caller");
    fixture.admit("new_caller");
    fixture.admit("target_module");
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"target_module":["old_caller"]})"), 0);

    CapabilityModuleImpl impl;
    std::string granted;
    {
        const auto oldCaller = logos::CallCaller::module("old_caller");
        granted = impl.requestModule("", "target_module");
        LOGOS_ASSERT(isUuid(granted));
    }

    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"target_module":["new_caller"]})"), 0);
    const auto revocations = revoked();
    LOGOS_ASSERT_EQ(revocations.size(), static_cast<size_t>(1));
    LOGOS_ASSERT_EQ(revocations[0].target, std::string("target_module"));
    LOGOS_ASSERT_EQ(revocations[0].caller, std::string("old_caller"));
    LOGOS_ASSERT_EQ(revocations[0].digest, digestOf(granted));

    {
        const auto oldCaller = logos::CallCaller::module("old_caller");
        LOGOS_ASSERT_TRUE(impl.requestModule("", "target_module").empty());
    }
    const auto newCaller = logos::CallCaller::module("new_caller");
    LOGOS_ASSERT(isUuid(impl.requestModule("", "target_module")));
}

LOGOS_TEST(requestModule_denies_spoofed_fromModuleName) {
    CapabilityFixture fixture;
    fixture.admit("package_manager_ui");
    fixture.admit("package_manager");
    fixture.admit("malicious_module");
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"package_manager":["package_manager_ui"]})"), 0);

    CapabilityModuleImpl impl;

    // Token-bound caller is malicious_module; leftover ABI claims the UI.
    const auto caller = logos::CallCaller::module("malicious_module");
    const std::string token = impl.requestModule("package_manager_ui", "package_manager");

    LOGOS_ASSERT_TRUE(token.empty());
}
