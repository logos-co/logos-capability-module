// The engine interface: capability_module as the store of record for the
// runtime's credentials and pair tokens.
#include <logos_test.h>
#include <logos_mock.h>
#include <logos_protocol.h>

#include "capability_authority.h"
#include "capability_module_impl.h"
#include "logos_capability_engine.h"

#include <nlohmann/json.hpp>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

extern "C" const logos_capability_engine_v1* logos_module_capability_engine_v1();

namespace {

const logos_capability_engine_v1& engine()
{
    return *logos_module_capability_engine_v1();
}

std::string take(char* value)
{
    std::string text = value ? value : "";
    engine().string_free(value);
    return text;
}

struct Admitted {
    std::string name;
    std::string credential;
    unsigned long long generation = 0;
};

Admitted admit(const std::string& name, const char* kind = "module")
{
    Admitted admitted{name, {}, 0};
    admitted.credential = take(engine().admit(name.c_str(), kind, &admitted.generation));
    return admitted;
}

std::mutex g_pushedMutex;
std::vector<CapabilityAuthority::Revocation> g_pushed;

// The revocations pushed so far, recorded rather than dialled.
std::vector<CapabilityAuthority::Revocation> pushed()
{
    CapabilityAuthority::instance().drainRevocations();
    std::lock_guard<std::mutex> lock(g_pushedMutex);
    return g_pushed;
}

std::string digestOf(const std::string& token)
{
    char* digest = lp_token_digest(token.c_str());
    std::string value = digest ? digest : "";
    lp_string_free(digest);
    return value;
}

// Every test starts from an empty store: retire whatever a test admitted, and
// let no revocation outlive the test.
struct Retiring {
    std::vector<Admitted> admitted;
    Retiring()
    {
        CapabilityAuthority::instance().setRevocationPush(
            [](const CapabilityAuthority::Revocation& revocation, const std::string&) {
                std::lock_guard<std::mutex> lock(g_pushedMutex);
                g_pushed.push_back(revocation);
                return LP_OK;
            });
    }
    ~Retiring()
    {
        for (const auto& a : admitted) engine().retire(a.name.c_str(), a.generation);
        engine().set_restrictions("{}");
        engine().set_caller_scopes("{}");
        engine().set_remote_policy("{}");
        CapabilityAuthority::instance().drainRevocations();
        std::lock_guard<std::mutex> lock(g_pushedMutex);
        g_pushed.clear();
    }
    Admitted add(const std::string& name, const char* kind = "module")
    {
        admitted.push_back(admit(name, kind));
        return admitted.back();
    }
};

} // namespace

LOGOS_TEST(engine_interface_is_sized_and_versioned) {
    LOGOS_ASSERT_EQ(engine().size, static_cast<unsigned>(sizeof(logos_capability_engine_v1)));
    LOGOS_ASSERT_EQ(engine().version, static_cast<unsigned>(LOGOS_CAPABILITY_ENGINE_VERSION));
}

LOGOS_TEST(an_admitted_credential_names_its_caller_until_retired) {
    LogosMockSetup mock;
    Retiring store;
    const Admitted mod = store.add("auth_mod_a");
    LOGOS_ASSERT_FALSE(mod.credential.empty());
    LOGOS_ASSERT_EQ(take(engine().credential_for("auth_mod_a")), mod.credential);
    const auto caller = nlohmann::json::parse(take(engine().resolve_caller(mod.credential.c_str(), "local")));
    LOGOS_ASSERT_EQ(caller, (nlohmann::json{{"kind", "module"}, {"name", "auth_mod_a"}}));
    LOGOS_ASSERT_EQ(engine().resolve_caller("not-a-credential", "local"), nullptr);

    LOGOS_ASSERT_EQ(engine().retire("auth_mod_a", mod.generation + 1), -1);
    LOGOS_ASSERT_EQ(engine().retire("auth_mod_a", mod.generation), 0);
    LOGOS_ASSERT_EQ(engine().resolve_caller(mod.credential.c_str(), "local"), nullptr);
    LOGOS_ASSERT_EQ(engine().credential_for("auth_mod_a"), nullptr);
    store.admitted.clear();
}

LOGOS_TEST(readmission_replaces_the_credential) {
    LogosMockSetup mock;
    Retiring store;
    const Admitted first = store.add("auth_mod_b");
    const Admitted second = store.add("auth_mod_b");
    LOGOS_ASSERT_NE(first.credential, second.credential);
    LOGOS_ASSERT_NE(first.generation, second.generation);
    LOGOS_ASSERT_EQ(engine().resolve_caller(first.credential.c_str(), "local"), nullptr);
    LOGOS_ASSERT_EQ(engine().retire("auth_mod_b", first.generation), -1);
    store.admitted.erase(store.admitted.begin());
}

LOGOS_TEST(an_unknown_kind_is_refused) {
    unsigned long long generation = 0;
    LOGOS_ASSERT_EQ(engine().admit("auth_mod_c", "operator", &generation), nullptr);
}

// A target on record needs no registry grant, and a pair keeps one token.
LOGOS_TEST(request_module_hands_one_token_per_admitted_pair) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    store.add("auth_caller");
    store.add("auth_target");

    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("auth_caller");
    const std::string first = impl.requestModule("", "auth_target");
    LOGOS_ASSERT_FALSE(first.empty());
    LOGOS_ASSERT_EQ(impl.requestModule("", "auth_target"), first);
    lp_grant_host_services("[]");
}

LOGOS_TEST(retiring_the_caller_forgets_its_pairs) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    Admitted callerId = store.add("auth_caller_r");
    store.add("auth_target_r");

    CapabilityModuleImpl impl;
    std::string first;
    {
        const auto caller = logos::CallCaller::module("auth_caller_r");
        first = impl.requestModule("", "auth_target_r");
    }
    LOGOS_ASSERT_EQ(engine().retire("auth_caller_r", callerId.generation), 0);
    store.admitted.erase(store.admitted.begin());
    const auto revocations = pushed();
    LOGOS_ASSERT_EQ(revocations.size(), static_cast<size_t>(1));
    LOGOS_ASSERT_EQ(revocations[0].target, std::string("auth_target_r"));
    LOGOS_ASSERT_EQ(revocations[0].caller, std::string("auth_caller_r"));
    LOGOS_ASSERT_EQ(revocations[0].digest, digestOf(first));
    store.add("auth_caller_r");
    const auto caller = logos::CallCaller::module("auth_caller_r");
    const std::string second = impl.requestModule("", "auth_target_r");
    LOGOS_ASSERT_FALSE(second.empty());
    LOGOS_ASSERT_NE(second, first);
    lp_grant_host_services("[]");
}

LOGOS_TEST(a_consumer_only_target_is_refused_fast) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    store.add("auth_caller_s");
    store.add("auth_shell", "shell");
    CapabilityModuleImpl impl;
    const auto caller = logos::CallCaller::module("auth_caller_s");
    LOGOS_ASSERT(impl.requestModule("", "auth_shell").empty());
    lp_grant_host_services("[]");
}

LOGOS_TEST(restrictions_from_the_engine_deny_a_pair) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    store.add("auth_allowed");
    store.add("auth_denied");
    store.add("auth_guarded");
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"auth_guarded":["auth_allowed"]})"), 0);
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"auth_guarded":"auth_allowed"})"), -1);

    CapabilityModuleImpl impl;
    {
        const auto caller = logos::CallCaller::module("auth_allowed");
        LOGOS_ASSERT_FALSE(impl.requestModule("", "auth_guarded").empty());
    }
    const auto caller = logos::CallCaller::module("auth_denied");
    LOGOS_ASSERT(impl.requestModule("", "auth_guarded").empty());
    lp_grant_host_services("[]");
}

LOGOS_TEST(an_operator_pair_is_granted_for_an_admitted_target) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    store.add("auth_op_target");
    const std::string token = take(engine().grant_operator_pair("alice", "auth_op_target"));
    LOGOS_ASSERT_FALSE(token.empty());
    LOGOS_ASSERT_EQ(take(engine().grant_operator_pair("alice", "auth_op_target")), token);
    LOGOS_ASSERT_EQ(engine().grant_operator_pair("alice", "not_admitted"), nullptr);
    lp_grant_host_services("[]");
}

LOGOS_TEST(a_stopped_authority_pushes_no_revocation) {
    CapabilityAuthority authority;
    std::atomic<int> pushes{0};
    authority.setRevocationPush([&](const CapabilityAuthority::Revocation&, const std::string&) {
        ++pushes;
        return LP_OK;
    });
    uint64_t callerGeneration = 0;
    uint64_t targetGeneration = 0;
    authority.admit("stop_caller", "module", callerGeneration);
    authority.admit("stop_target", "module", targetGeneration);
    authority.recordPair("stop_caller", "stop_target", "stop_token");
    authority.stopRevocations();
    LOGOS_ASSERT(authority.retire("stop_caller", callerGeneration));
    authority.drainRevocations();
    LOGOS_ASSERT_EQ(pushes.load(), 0);
}

// ── peering ──────────────────────────────────────────────────────────────────

LOGOS_TEST(the_remote_policy_decides_remote_access) {
    Retiring store;
    const auto decide = [](const char* peer, const char* consumer, const char* target) {
        return nlohmann::json::parse(take(engine().evaluate_remote_access(peer, consumer, target)));
    };
    LOGOS_ASSERT(LOGOS_CAPABILITY_ENGINE_HAS(&engine(), set_caller_scopes));
    LOGOS_ASSERT_EQ(engine().set_remote_policy(
        R"({"peer-a/wallet":["auth_wallet"],"peer-b/*":["*"]})"), 0);
    LOGOS_ASSERT(decide("peer-a", "wallet", "auth_wallet").value("allow", false));
    LOGOS_ASSERT_FALSE(decide("peer-a", "wallet", "auth_wallet").value("decision", "").empty());
    // Unlisted consumer, target or runtime: denied.
    LOGOS_ASSERT_FALSE(decide("peer-a", "miner", "auth_wallet").value("allow", true));
    LOGOS_ASSERT_FALSE(decide("peer-a", "wallet", "other").value("allow", true));
    LOGOS_ASSERT_FALSE(decide("peer-c", "wallet", "auth_wallet").value("allow", true));
    // "*" as the consumer and as the target.
    LOGOS_ASSERT(decide("peer-b", "anyone", "anything").value("allow", false));
    LOGOS_ASSERT_EQ(engine().set_remote_policy(R"({"no-runtime":["x"]})"), -1);
    LOGOS_ASSERT_EQ(engine().set_remote_policy(R"({"peer-a/wallet":"auth_wallet"})"), -1);
    LOGOS_ASSERT_EQ(engine().set_remote_policy("{}"), 0);
    LOGOS_ASSERT_FALSE(decide("peer-b", "anyone", "anything").value("allow", true));
}

LOGOS_TEST(a_scoped_caller_pairs_only_within_its_scope) {
    LogosMockSetup mock;
    lp_grant_host_services(R"(["token_delivery"])");
    Retiring store;
    store.add("auth_facade");
    store.add("auth_peering");
    store.add("auth_other");
    CapabilityModuleImpl impl;
    std::string held;
    {
        const auto caller = logos::CallCaller::module("auth_facade");
        held = impl.requestModule("", "auth_other");
        LOGOS_ASSERT_FALSE(held.empty());
    }
    LOGOS_ASSERT_EQ(engine().set_caller_scopes(R"({"auth_facade":["auth_peering"]})"), 0);
    // The pair it held outside its new scope is revoked at once.
    const auto revocations = pushed();
    LOGOS_ASSERT_EQ(revocations.size(), static_cast<size_t>(1));
    LOGOS_ASSERT_EQ(revocations[0].target, std::string("auth_other"));
    LOGOS_ASSERT_EQ(revocations[0].digest, digestOf(held));
    const auto caller = logos::CallCaller::module("auth_facade");
    LOGOS_ASSERT(impl.requestModule("", "auth_other").empty());
    LOGOS_ASSERT_FALSE(impl.requestModule("", "auth_peering").empty());
    LOGOS_ASSERT_EQ(engine().set_caller_scopes(R"({"auth_facade":"auth_peering"})"), -1);
    lp_grant_host_services("[]");
}
