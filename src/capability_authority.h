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

    // What a caller may call at a target: nothing, every method, or a list.
    struct Grant {
        enum class Kind { None, All, Methods };
        Kind kind = Kind::None;
        std::set<std::string> methods;

        static Grant all() { return {Kind::All, {}}; }
        bool operator==(const Grant& other) const
        {
            return kind == other.kind && methods == other.methods;
        }
        bool operator!=(const Grant& other) const { return !(*this == other); }
        // "*", a JSON array of methods, or [] for none.
        std::string json() const;
    };

    // A fresh credential for `name` ("module", "shell" or "presentation"); empty
    // when refused. A re-admission retires the previous one. A pending admission
    // is no target until openTarget.
    std::string admit(const std::string& name, const std::string& kind, uint64_t& generation,
                      bool pending = false);
    bool openTarget(const std::string& name);
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

    // Version 1: {"<target>":["<caller>",...]}; a target absent is unrestricted and
    // operators are not bound. Version 2 (logos_capability_engine.h) binds them.
    bool setRestrictions(const std::string& json);
    bool setAccessRules(const std::string& json);
    Grant grantFor(const std::string& caller, const std::string& target) const;
    bool allows(const std::string& caller, const std::string& target) const;

    // The token `caller` presents to `target`, pushed to the target under the
    // pair's grant (scoped for a method list); empty when refused, with `why`.
    // One push per pair at a time, and a pair withdrawn while its push was in
    // flight is revoked rather than returned.
    std::string issuePair(const std::string& caller, const std::string& target,
                          std::string* why = nullptr);

    // A token push to a target (LP_OK when it took); `scope` makes it scoped.
    struct Push {
        std::string target;
        std::string caller;
        std::string token;
        std::string auth;
        std::optional<std::string> scope;
    };
    using TokenPush = std::function<int(const Push&)>;
    // Replaces the push (tests); empty restores it.
    void setTokenPush(TokenPush push);

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
    using Rule = std::map<std::string, Grant>;
    std::optional<std::map<std::string, Rule>> parseRules(const std::string& json,
                                                          bool objects) const;
    void replaceRules(std::map<std::string, Rule> rules, bool operatorsBound);
    Grant evaluate(const std::string& caller, const std::string& target) const;
    void queueRevocations(std::vector<Revocation> revocations);
    void runRevocations();

    struct Identity {
        std::string credential;
        std::string kind;
        uint64_t generation = 0;
        bool open = true;
    };
    struct Pair {
        std::string token;
        Grant grant;
        bool pushing = false;
    };

    mutable std::mutex m_mutex;
    std::condition_variable m_pairChanged;
    std::map<std::string, Identity> m_identities;
    std::map<std::pair<std::string, std::string>, Pair> m_pairs;
    std::map<std::string, Rule> m_rules;
    bool m_operatorsBound = false;
    TokenPush m_tokenPush;
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
