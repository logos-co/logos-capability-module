// The engine interface: capability_module as the store of record for the
// runtime's credentials and pair tokens.
#include <logos_test.h>
#include <logos_mock.h>
#include <logos_protocol.h>

#include "capability_authority.h"
#include "capability_module_impl.h"
#include "logos_capability_engine.h"

#include <nlohmann/json.hpp>

#include <string>

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

// Every test starts from an empty store: retire whatever a test admitted.
struct Retiring {
    std::vector<Admitted> admitted;
    ~Retiring()
    {
        for (const auto& a : admitted) engine().retire(a.name.c_str(), a.generation);
        engine().set_restrictions("{}");
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
