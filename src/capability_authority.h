#pragma once

// The store of record for the runtime's credentials and pair tokens, driven by the
// engine through logos_capability_engine_v1. A pair's raw token lives in memory
// only; revocation names it by digest.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

class CapabilityAuthority {
public:
    static CapabilityAuthority& instance();
    ~CapabilityAuthority();

    // A fresh random token: every credential and pair token comes from here.
    static std::string mintToken();

    // A fresh credential for `name` ("module", "shell" or "presentation"); empty
    // when refused. A re-admission retires the previous one.
    std::string admit(const std::string& name, const std::string& kind, uint64_t& generation);
    bool retire(const std::string& name, uint64_t generation);
    std::optional<std::string> nameForCredential(const std::string& token) const;
    std::string credentialFor(const std::string& name) const;
    bool isAdmitted(const std::string& name) const;
    // Shells and presentation consumers call; nothing calls them.
    bool isConsumerOnly(const std::string& name) const;

    // The token `caller` holds for `target` while the pair is valid; empty for none.
    std::string pairToken(const std::string& caller, const std::string& target) const;
    void recordPair(const std::string& caller, const std::string& target, const std::string& token);
    void forgetPair(const std::string& caller, const std::string& target);

    // {"<target>":["<caller>",...]}; a target absent is unrestricted.
    bool setRestrictions(const std::string& json);
    bool allows(const std::string& caller, const std::string& target) const;

    // Revocations of tokens held at targets that are still admitted, pushed in
    // order by one worker the authority owns.
    struct Revocation {
        std::string target;
        std::string caller;
        std::string digest;
    };
    // Replaces the push to the target (LP_OK when it took); empty restores it.
    using RevocationPush = std::function<int(const Revocation&, const std::string& auth)>;
    void setRevocationPush(RevocationPush push);
    // Returns once every queued revocation was pushed or given up on.
    void drainRevocations();
    // Drops what is queued and joins the worker; nothing is pushed afterwards.
    void stopRevocations();

private:
    void queueRevocations(std::vector<Revocation> revocations);
    void runRevocations();

    struct Identity {
        std::string credential;
        std::string kind;
        uint64_t generation = 0;
    };

    mutable std::mutex m_mutex;
    std::map<std::string, Identity> m_identities;
    std::map<std::pair<std::string, std::string>, std::string> m_pairs;
    std::map<std::string, std::set<std::string>> m_restrictions;
    uint64_t m_nextGeneration = 1;

    std::mutex m_pushMutex;
    std::condition_variable m_pushWake;
    std::condition_variable m_pushIdle;
    std::deque<Revocation> m_revocations;
    RevocationPush m_push;
    std::thread m_pushWorker;
    bool m_pushing = false;
    std::atomic<bool> m_pushStopped{false};
};
