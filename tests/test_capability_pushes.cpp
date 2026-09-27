// One push per pair at a time, and a pair withdrawn while its token was being pushed
// is revoked after the push instead of being returned.
#include "recording_pushes.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace recording;

// Detector: two first requests each minted, recorded and pushed, and the target
// kept whichever push landed last. The second waits for the first push to land.
LOGOS_TEST(concurrent_requests_for_one_pair_mint_one_token) {
    Pushes pushes;
    pushes.admit("p_race_caller");
    pushes.admit("p_race_target");
    pushes.hold();
    std::string first;
    std::string second;
    std::atomic<bool> secondReturned{false};
    std::thread a([&] { first = request("p_race_caller", "p_race_target"); });
    const bool started = pushes.started(1);
    std::thread b([&] {
        second = request("p_race_caller", "p_race_target");
        secondReturned = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const bool returnedBeforeDelivery = secondReturned.load();
    pushes.release();
    a.join();
    b.join();
    LOGOS_ASSERT(started);
    LOGOS_ASSERT_FALSE(returnedBeforeDelivery);
    LOGOS_ASSERT_FALSE(first.empty());
    LOGOS_ASSERT_EQ(first, second);
    LOGOS_ASSERT_EQ(pushes.pushes().size(), static_cast<size_t>(1));
}

// Detector: a policy change during the push queued a revocation that could run
// before the push landed and fail; the token then stayed live, unrecorded.
LOGOS_TEST(a_push_overtaken_by_a_new_policy_is_withdrawn) {
    Pushes pushes;
    pushes.admit("p_late_caller");
    pushes.admit("p_late_target");
    pushes.hold();
    std::string token = "unset";
    std::thread a([&] { token = request("p_late_caller", "p_late_target"); });
    const bool started = pushes.started(1);
    const int ruled = engine().set_restrictions(R"({"p_late_target":["someone_else"]})");
    pushes.release();
    a.join();
    LOGOS_ASSERT(started);
    LOGOS_ASSERT_EQ(ruled, 0);
    const std::string pushed = pushes.pushes().at(0).token;
    LOGOS_ASSERT(token.empty());
    const auto revoked = pushes.revoked();
    LOGOS_ASSERT_FALSE(revoked.empty());
    LOGOS_ASSERT_EQ(revoked.back().digest, digestOf(pushed));
    LOGOS_ASSERT(CapabilityAuthority::instance().pairToken("p_late_caller", "p_late_target").empty());
}

LOGOS_TEST(a_caller_retired_during_its_push_does_not_keep_the_pair) {
    Pushes pushes;
    pushes.admit("p_gone_caller");
    pushes.admit("p_gone_target");
    pushes.hold();
    std::string token = "unset";
    std::thread a([&] { token = request("p_gone_caller", "p_gone_target"); });
    const bool started = pushes.started(1);
    pushes.retire("p_gone_caller");
    pushes.release();
    a.join();
    LOGOS_ASSERT(started);
    const std::string pushed = pushes.pushes().at(0).token;
    LOGOS_ASSERT(token.empty());
    const auto revoked = pushes.revoked();
    LOGOS_ASSERT_FALSE(revoked.empty());
    LOGOS_ASSERT_EQ(revoked.back().digest, digestOf(pushed));
}

LOGOS_TEST(a_failed_push_leaves_no_pair) {
    Pushes pushes;
    pushes.admit("p_fail_caller");
    pushes.admit("p_fail_target");
    pushes.answer(LP_ERR_INTERNAL);
    LOGOS_ASSERT(request("p_fail_caller", "p_fail_target").empty());
    LOGOS_ASSERT(CapabilityAuthority::instance().pairToken("p_fail_caller", "p_fail_target").empty());
    LOGOS_ASSERT(pushes.revoked().empty());
}
