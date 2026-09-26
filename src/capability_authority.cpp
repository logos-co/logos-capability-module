#include "capability_authority.h"
#include "logos_capability_engine.h"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <logos_host_services.h>
#include <logos_module_impl.h>
#include <logos_protocol.h>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {

constexpr int kPushTimeoutMs = 3000;
constexpr int kRevocationAttempts = 3;


std::string digestOf(const std::string& token)
{
    char* digest = lp_token_digest(token.c_str());
    std::string value = digest ? digest : "";
    lp_string_free(digest);
    return value;
}

int pushToTarget(const CapabilityAuthority::Revocation& revocation, const std::string& auth)
{
    lp_client* client =
        lp_client_create(revocation.target.c_str(), "capability_module", nullptr, nullptr);
    const int status = client ? lp_revoke_module_token_to(
                                    client, auth.c_str(), revocation.target.c_str(),
                                    revocation.caller.c_str(), revocation.digest.c_str(),
                                    kPushTimeoutMs)
                              : LP_ERR_UNAVAILABLE;
    if (client) lp_client_destroy(client);
    return status;
}

} // namespace

// Boost seeds from the platform CSPRNG; std::random_device may be deterministic
// (it was on MinGW), and the token IS the secret.
std::string CapabilityAuthority::mintToken()
{
    static std::mutex mutex;
    static boost::uuids::random_generator generator;
    std::lock_guard<std::mutex> lock(mutex);
    return boost::uuids::to_string(generator());
}

CapabilityAuthority& CapabilityAuthority::instance()
{
    // Leaked: a static destructor must not join the worker (on Windows it runs
    // under the loader lock); aboutToUnload() stops it instead.
    static auto* authority = new CapabilityAuthority;
    return *authority;
}

CapabilityAuthority::~CapabilityAuthority()
{
    stopRevocations();
}

void CapabilityAuthority::setRevocationPush(RevocationPush push)
{
    std::lock_guard<std::mutex> lock(m_pushMutex);
    m_push = std::move(push);
}

void CapabilityAuthority::queueRevocations(std::vector<Revocation> revocations)
{
    if (revocations.empty()) return;
    std::lock_guard<std::mutex> lock(m_pushMutex);
    if (m_pushStopped) return;
    for (auto& revocation : revocations) m_revocations.push_back(std::move(revocation));
    if (!m_pushWorker.joinable()) m_pushWorker = std::thread([this] { runRevocations(); });
    m_pushWake.notify_one();
}

void CapabilityAuthority::runRevocations()
{
    std::unique_lock<std::mutex> lock(m_pushMutex);
    for (;;) {
        m_pushWake.wait(lock, [this] { return m_pushStopped || !m_revocations.empty(); });
        if (m_pushStopped) return;
        const Revocation revocation = std::move(m_revocations.front());
        m_revocations.pop_front();
        const RevocationPush push = m_push;
        m_pushing = true;
        lock.unlock();
        const std::string auth = credentialFor(revocation.target);
        int status = auth.empty() ? LP_OK : LP_ERR_INTERNAL; // empty: the target is gone too
        for (int attempt = 0; attempt < kRevocationAttempts && status != LP_OK && !m_pushStopped;
             ++attempt)
            status = push ? push(revocation, auth) : pushToTarget(revocation, auth);
        if (status != LP_OK && !m_pushStopped)
            std::fprintf(stderr, "[capability_module] could not revoke %s's token at %s\n",
                         revocation.caller.c_str(), revocation.target.c_str());
        lock.lock();
        m_pushing = false;
        m_pushIdle.notify_all();
    }
}

void CapabilityAuthority::drainRevocations()
{
    std::unique_lock<std::mutex> lock(m_pushMutex);
    m_pushIdle.wait(lock, [this] {
        return m_pushStopped || (m_revocations.empty() && !m_pushing);
    });
}

void CapabilityAuthority::stopRevocations()
{
    std::thread worker;
    {
        // Notified under the lock: mingw's condvar can lose a notify after unlock.
        std::lock_guard<std::mutex> lock(m_pushMutex);
        m_pushStopped = true;
        m_revocations.clear();
        worker = std::move(m_pushWorker);
        m_pushWake.notify_all();
        m_pushIdle.notify_all();
    }
    if (worker.joinable()) worker.join();
}

std::string CapabilityAuthority::admit(const std::string& name, const std::string& kind,
                                       uint64_t& generation)
{
    if (name.empty() || (kind != "module" && kind != "shell" && kind != "presentation"))
        return {};
    std::string credential = CapabilityAuthority::mintToken();
    uint64_t previous = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (auto it = m_identities.find(name); it != m_identities.end())
            previous = it->second.generation;
    }
    if (previous) retire(name, previous);
    std::lock_guard<std::mutex> lock(m_mutex);
    generation = m_nextGeneration++;
    m_identities[name] = Identity{credential, kind, generation};
    return credential;
}

bool CapabilityAuthority::retire(const std::string& name, uint64_t generation)
{
    std::vector<Revocation> revocations;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_identities.find(name);
        if (it == m_identities.end() || it->second.generation != generation) return false;
        m_identities.erase(it);
        for (auto pair = m_pairs.begin(); pair != m_pairs.end();) {
            const auto& [caller, target] = pair->first;
            if (caller != name && target != name) {
                ++pair;
                continue;
            }
            // What `name` holds elsewhere is withdrawn there; what others hold
            // for `name` died with it.
            if (caller == name && m_identities.count(target))
                revocations.push_back({target, caller, digestOf(pair->second)});
            pair = m_pairs.erase(pair);
        }
    }
    queueRevocations(std::move(revocations));
    return true;
}

std::optional<std::string> CapabilityAuthority::nameForCredential(const std::string& token) const
{
    if (token.empty()) return std::nullopt;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [name, identity] : m_identities)
        if (logos::host::constantTimeEquals(identity.credential, token)) return name;
    return std::nullopt;
}

std::string CapabilityAuthority::credentialFor(const std::string& name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_identities.find(name);
    return it == m_identities.end() ? std::string{} : it->second.credential;
}

bool CapabilityAuthority::isAdmitted(const std::string& name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_identities.count(name) > 0;
}

bool CapabilityAuthority::isConsumerOnly(const std::string& name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_identities.find(name);
    return it != m_identities.end() && it->second.kind != "module";
}

std::string CapabilityAuthority::pairToken(const std::string& caller,
                                           const std::string& target) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_pairs.find({caller, target});
    return it == m_pairs.end() ? std::string{} : it->second;
}

void CapabilityAuthority::recordPair(const std::string& caller, const std::string& target,
                                     const std::string& token)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pairs[{caller, target}] = token;
}

void CapabilityAuthority::forgetPair(const std::string& caller, const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pairs.erase({caller, target});
}

bool CapabilityAuthority::setRestrictions(const std::string& text)
{
    const nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
    if (!doc.is_object()) return false;
    std::map<std::string, std::set<std::string>> restrictions;
    for (const auto& [target, callers] : doc.items()) {
        if (!callers.is_array()) return false;
        auto& allowed = restrictions[target];
        for (const auto& caller : callers) {
            if (!caller.is_string()) return false;
            allowed.insert(caller.get<std::string>());
        }
    }
    std::vector<Revocation> revocations;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_restrictions = std::move(restrictions);
        // Pairs the new policy denies stop working now, not at their next request.
        for (auto pair = m_pairs.begin(); pair != m_pairs.end();) {
            const auto& [caller, target] = pair->first;
            auto rule = m_restrictions.find(target);
            if (rule == m_restrictions.end() || rule->second.count(caller)) {
                ++pair;
                continue;
            }
            if (m_identities.count(target)) revocations.push_back({target, caller, digestOf(pair->second)});
            pair = m_pairs.erase(pair);
        }
    }
    queueRevocations(std::move(revocations));
    return true;
}

bool CapabilityAuthority::allows(const std::string& caller, const std::string& target) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto rule = m_restrictions.find(target);
    return rule == m_restrictions.end() || rule->second.count(caller) > 0;
}

namespace {

// {"<key>":["<name>",...]}, or nothing when malformed.
std::optional<std::map<std::string, std::set<std::string>>> nameLists(const std::string& text)
{
    const nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
    if (!doc.is_object()) return std::nullopt;
    std::map<std::string, std::set<std::string>> lists;
    for (const auto& [key, names] : doc.items()) {
        if (key.empty() || !names.is_array()) return std::nullopt;
        auto& list = lists[key];
        for (const auto& name : names) {
            if (!name.is_string() || name.get<std::string>().empty()) return std::nullopt;
            list.insert(name.get<std::string>());
        }
    }
    return lists;
}

} // namespace

bool CapabilityAuthority::setRemotePolicy(const std::string& text)
{
    auto policy = nameLists(text);
    if (!policy) return false;
    for (const auto& [key, targets] : *policy) {
        const auto slash = key.find('/');
        if (slash == 0 || slash == std::string::npos || slash + 1 == key.size()) return false;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_remotePolicy = std::move(*policy);
    return true;
}

bool CapabilityAuthority::allowsRemote(const std::string& peer, const std::string& consumer,
                                       const std::string& target) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const std::string& key : {peer + "/" + consumer, peer + "/*"}) {
        const auto rule = m_remotePolicy.find(key);
        if (rule != m_remotePolicy.end() && (rule->second.count(target) || rule->second.count("*")))
            return true;
    }
    return false;
}

bool CapabilityAuthority::setCallerScopes(const std::string& text)
{
    auto scopes = nameLists(text);
    if (!scopes) return false;
    std::vector<Revocation> revocations;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_scopes = std::move(*scopes);
        // A pair outside its caller's new scope stops working now.
        for (auto pair = m_pairs.begin(); pair != m_pairs.end();) {
            const auto& [caller, target] = pair->first;
            const auto scope = m_scopes.find(caller);
            if (scope == m_scopes.end() || scope->second.count(target)) {
                ++pair;
                continue;
            }
            if (m_identities.count(target)) revocations.push_back({target, caller, digestOf(pair->second)});
            pair = m_pairs.erase(pair);
        }
    }
    queueRevocations(std::move(revocations));
    return true;
}

bool CapabilityAuthority::withinScope(const std::string& caller, const std::string& target) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto scope = m_scopes.find(caller);
    return scope == m_scopes.end() || scope->second.count(target) > 0;
}

// ── logos_capability_engine_v1 ────────────────────────────────────────────────

namespace {

char* copy(const std::string& value)
{
    auto* result = static_cast<char*>(std::malloc(value.size() + 1));
    if (result) std::memcpy(result, value.c_str(), value.size() + 1);
    return result;
}

char* engineAdmit(const char* name, const char* kind, unsigned long long* generation)
{
    if (!name || !kind || !generation) return nullptr;
    uint64_t admitted = 0;
    const std::string credential = CapabilityAuthority::instance().admit(name, kind, admitted);
    if (credential.empty()) return nullptr;
    *generation = admitted;
    return copy(credential);
}

int engineRetire(const char* name, unsigned long long generation)
{
    return name && CapabilityAuthority::instance().retire(name, generation) ? 0 : -1;
}

char* engineResolveCaller(const char* token, const char* /*transport*/)
{
    if (!token) return nullptr;
    const auto name = CapabilityAuthority::instance().nameForCredential(token);
    return name ? copy(nlohmann::json{{"kind", "module"}, {"name", *name}}.dump()) : nullptr;
}

char* engineCredentialFor(const char* name)
{
    if (!name) return nullptr;
    const std::string credential = CapabilityAuthority::instance().credentialFor(name);
    return credential.empty() ? nullptr : copy(credential);
}

// The target learns the token as "@op:<op>", a key no module name can take.
char* engineGrantOperatorPair(const char* op, const char* target)
{
    if (!op || !*op || !target) return nullptr;
    CapabilityAuthority& authority = CapabilityAuthority::instance();
    const std::string key = std::string("@op:") + op;
    if (std::string existing = authority.pairToken(key, target); !existing.empty())
        return copy(existing);
    const std::string auth = authority.credentialFor(target);
    if (auth.empty() || authority.isConsumerOnly(target)) return nullptr;
    const std::string token = CapabilityAuthority::mintToken();
    authority.recordPair(key, target, token);
    lp_client* client = lp_client_create(target, "capability_module", nullptr, nullptr);
    const int status = client ? lp_inform_module_token_to(client, auth.c_str(), target,
                                                          key.c_str(), token.c_str(),
                                                          kPushTimeoutMs)
                              : LP_ERR_UNAVAILABLE;
    if (client) lp_client_destroy(client);
    if (status != LP_OK) {
        authority.forgetPair(key, target);
        return nullptr;
    }
    return copy(token);
}

int engineSetRestrictions(const char* json)
{
    return json && CapabilityAuthority::instance().setRestrictions(json) ? 0 : -1;
}

char* engineEvaluateRemoteAccess(const char* peer, const char* consumer, const char* target)
{
    if (!peer || !consumer || !target) return nullptr;
    const bool allow = CapabilityAuthority::instance().allowsRemote(peer, consumer, target);
    // Names this decision in the audit of the runtime that asked.
    const std::string decision = CapabilityAuthority::mintToken();
    return copy(nlohmann::json{{"allow", allow}, {"decision", decision}}.dump());
}

int engineSetRemotePolicy(const char* json)
{
    return json && CapabilityAuthority::instance().setRemotePolicy(json) ? 0 : -1;
}

int engineSetCallerScopes(const char* json)
{
    return json && CapabilityAuthority::instance().setCallerScopes(json) ? 0 : -1;
}

void engineStringFree(char* value)
{
    std::free(value);
}

const logos_capability_engine_v1 kEngine = {
    sizeof(logos_capability_engine_v1),
    LOGOS_CAPABILITY_ENGINE_VERSION,
    &engineAdmit,
    &engineRetire,
    &engineResolveCaller,
    &engineCredentialFor,
    &engineGrantOperatorPair,
    &engineSetRestrictions,
    &engineStringFree,
    &engineEvaluateRemoteAccess,
    &engineSetRemotePolicy,
    &engineSetCallerScopes,
};

} // namespace

extern "C" LOGOS_MODULE_IMPL_EXPORT const logos_capability_engine_v1* logos_module_capability_engine_v1()
{
    return &kEngine;
}
