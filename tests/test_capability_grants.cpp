// Engine version 2: access rules with per-caller method grants, pairs kept with their
// grant, scoped pushes and pending targets.
#include "recording_pushes.h"

#include <nlohmann/json.hpp>

#include <string>

using namespace recording;

namespace {

std::string grantFor(const char* caller, const char* target)
{
    return take(engine().grant_for(caller, target));
}

} // namespace

LOGOS_TEST(an_exact_caller_wins_then_the_wildcards_and_entries_never_merge) {
    Pushes grants;
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({
        "g_t": {"exact": ["m1"], "*": ["m2"], "@op:*": ["m3"], "@op:bob": "*"},
        "g_ops_only": {"@op:*": "*"},
        "g_modules_only": {"*": "*"},
        "g_listed": ["listed", "@op:*"]
    })"), 0);
    LOGOS_ASSERT_EQ(grantFor("exact", "g_t"), std::string(R"(["m1"])"));
    LOGOS_ASSERT_EQ(grantFor("anyone", "g_t"), std::string(R"(["m2"])"));
    LOGOS_ASSERT_EQ(grantFor("@op:alice", "g_t"), std::string(R"(["m3"])"));
    LOGOS_ASSERT_EQ(grantFor("@op:bob", "g_t"), std::string(R"("*")"));
    LOGOS_ASSERT_EQ(grantFor("a_module", "g_ops_only"), std::string("[]"));
    LOGOS_ASSERT_EQ(grantFor("@op:alice", "g_modules_only"), std::string("[]"));
    LOGOS_ASSERT_EQ(grantFor("listed", "g_listed"), std::string(R"("*")"));
    LOGOS_ASSERT_EQ(grantFor("@op:carol", "g_listed"), std::string(R"("*")"));
    LOGOS_ASSERT_EQ(grantFor("stranger", "g_listed"), std::string("[]"));
    LOGOS_ASSERT_EQ(grantFor("anyone", "g_unlisted"), std::string(R"("*")"));
}

LOGOS_TEST(version_1_restrictions_leave_operators_unbound) {
    Pushes grants;
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"g_v1":["a"]})"), 0);
    LOGOS_ASSERT_EQ(grantFor("@op:alice", "g_v1"), std::string(R"("*")"));
    LOGOS_ASSERT_EQ(grantFor("b", "g_v1"), std::string("[]"));
    LOGOS_ASSERT_EQ(engine().set_restrictions(R"({"g_v1":{"a":"*"}})"), -1);
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({"g_v1":["a"]})"), 0);
    LOGOS_ASSERT_EQ(grantFor("@op:alice", "g_v1"), std::string("[]"));
}

LOGOS_TEST(a_malformed_document_changes_nothing) {
    Pushes grants;
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({"g_m":{"a":"*"}})"), 0);
    for (const char* bad : {R"({"g_m":{"a":"all"}})", R"({"g_m":{"a":["x","x"]}})",
                            R"({"g_m":{"a":["*"]}})", R"({"g_m":{"a":[""]}})",
                            R"({"g_m":5})", R"({"":["a"]})", R"({"g_m":{"":"*"}})", "[]",
                            "not json"})
        LOGOS_ASSERT_EQ(engine().set_access_rules(bad), -1);
    LOGOS_ASSERT_EQ(grantFor("a", "g_m"), std::string(R"("*")"));
}

LOGOS_TEST(an_empty_list_denies) {
    Pushes grants;
    grants.admit("g_empty_caller");
    grants.admit("g_empty_target");
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({"g_empty_target":{"g_empty_caller":[]}})"), 0);
    LOGOS_ASSERT_EQ(grantFor("g_empty_caller", "g_empty_target"), std::string("[]"));
    LOGOS_ASSERT(request("g_empty_caller", "g_empty_target").empty());
    LOGOS_ASSERT(grants.pushes().empty());
}

LOGOS_TEST(a_method_list_is_pushed_scoped_and_everything_else_unscoped) {
    Pushes grants;
    grants.admit("g_scope_caller");
    grants.admit("g_scope_other");
    grants.admit("g_scope_target");
    LOGOS_ASSERT_EQ(engine().set_access_rules(
        R"({"g_scope_target":{"g_scope_caller":["m2","m1"],"*":"*"}})"), 0);
    const std::string scoped = request("g_scope_caller", "g_scope_target");
    const std::string open = request("g_scope_other", "g_scope_target");
    LOGOS_ASSERT_FALSE(scoped.empty());
    LOGOS_ASSERT_FALSE(open.empty());
    const auto pushes = grants.pushes();
    LOGOS_ASSERT_EQ(pushes.size(), static_cast<size_t>(2));
    LOGOS_ASSERT(pushes[0].scope.has_value());
    LOGOS_ASSERT_EQ(nlohmann::json::parse(*pushes[0].scope),
                    (nlohmann::json{{"methods", {"m1", "m2"}}}));
    LOGOS_ASSERT_EQ(pushes[0].caller, std::string("g_scope_caller"));
    LOGOS_ASSERT_EQ(pushes[0].target, std::string("g_scope_target"));
    LOGOS_ASSERT_FALSE(pushes[1].scope.has_value());
}

// A target that cannot take a scoped push is refused, never given the token unscoped.
LOGOS_TEST(an_unsupported_target_is_refused_not_pushed_unscoped) {
    Pushes grants;
    grants.admit("g_old_caller");
    grants.admit("g_old_target");
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({"g_old_target":{"g_old_caller":["m"]}})"), 0);
    grants.answer(LP_ERR_TARGET_UNSUPPORTED);
    LOGOS_ASSERT(request("g_old_caller", "g_old_target").empty());
    const auto pushes = grants.pushes();
    LOGOS_ASSERT_EQ(pushes.size(), static_cast<size_t>(1));
    LOGOS_ASSERT(pushes[0].scope.has_value());
    LOGOS_ASSERT(CapabilityAuthority::instance().pairToken("g_old_caller", "g_old_target").empty());
}

LOGOS_TEST(a_changed_grant_revokes_and_an_unchanged_one_keeps_its_pair) {
    Pushes grants;
    grants.admit("g_keep_caller");
    grants.admit("g_keep_target");
    const char* rules = R"({"g_keep_target":{"g_keep_caller":["m1"],"@op:*":"*"}})";
    LOGOS_ASSERT_EQ(engine().set_access_rules(rules), 0);
    const std::string first = request("g_keep_caller", "g_keep_target");
    const std::string op = take(engine().grant_operator_pair("alice", "g_keep_target"));
    LOGOS_ASSERT_FALSE(first.empty());
    LOGOS_ASSERT_FALSE(op.empty());

    LOGOS_ASSERT_EQ(engine().set_access_rules(rules), 0);
    LOGOS_ASSERT(grants.revoked().empty());
    LOGOS_ASSERT_EQ(request("g_keep_caller", "g_keep_target"), first);
    LOGOS_ASSERT_EQ(take(engine().grant_operator_pair("alice", "g_keep_target")), op);

    LOGOS_ASSERT_EQ(engine().set_access_rules(
        R"({"g_keep_target":{"g_keep_caller":["m1","m2"],"@op:*":"*"}})"), 0);
    const auto revoked = grants.revoked();
    LOGOS_ASSERT_EQ(revoked.size(), static_cast<size_t>(1));
    LOGOS_ASSERT_EQ(revoked[0].caller, std::string("g_keep_caller"));
    LOGOS_ASSERT_EQ(revoked[0].digest, digestOf(first));
    const std::string second = request("g_keep_caller", "g_keep_target");
    LOGOS_ASSERT_FALSE(second.empty());
    LOGOS_ASSERT_NE(second, first);
    LOGOS_ASSERT_EQ(take(engine().grant_operator_pair("alice", "g_keep_target")), op);
}

LOGOS_TEST(operators_need_an_entry_under_access_rules) {
    Pushes grants;
    grants.admit("g_op_target");
    LOGOS_ASSERT_EQ(engine().set_access_rules(R"({"g_op_target":{"@op:bob":["list"]}})"), 0);
    LOGOS_ASSERT_EQ(engine().grant_operator_pair("alice", "g_op_target"), nullptr);
    const std::string bob = take(engine().grant_operator_pair("bob", "g_op_target"));
    LOGOS_ASSERT_FALSE(bob.empty());
    const auto pushes = grants.pushes();
    LOGOS_ASSERT_EQ(pushes.size(), static_cast<size_t>(1));
    LOGOS_ASSERT_EQ(pushes[0].caller, std::string("@op:bob"));
    LOGOS_ASSERT(pushes[0].scope.has_value());
}

LOGOS_TEST(a_pending_target_refuses_pairing_until_opened) {
    Pushes grants;
    grants.admit("g_pend_caller");
    grants.admit("g_pend_target", true);
    LOGOS_ASSERT(request("g_pend_caller", "g_pend_target").empty());
    LOGOS_ASSERT_EQ(engine().grant_operator_pair("alice", "g_pend_target"), nullptr);
    LOGOS_ASSERT(grants.pushes().empty());
    LOGOS_ASSERT_EQ(engine().open_target("g_pend_target"), 0);
    LOGOS_ASSERT_FALSE(request("g_pend_caller", "g_pend_target").empty());
    LOGOS_ASSERT_EQ(engine().open_target("g_never_admitted"), -1);
}
