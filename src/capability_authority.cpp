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

int pushTokenToTarget(const CapabilityAuthority::Push& push)
{
    lp_client* client = lp_client_create(push.target.c_str(), "capability_module", nullptr, nullptr);
    if (!client) return LP_ERR_UNAVAILABLE;
    const int status = push.scope
        ? lp_inform_scoped_module_token_to(client, push.auth.c_str(), push.target.c_str(),
                                           push.caller.c_str(), push.token.c_str(),
                                           push.scope->c_str(), kPushTimeoutMs)
        : lp_inform_module_token_to(client, push.auth.c_str(), push.target.c_str(),
                                    push.caller.c_str(), push.token.c_str(), kPushTimeoutMs);
    lp_client_destroy(client);
    return status;
}

std::string pushFailure(int status)
{
    if (status == LP_ERR_TARGET_UNSUPPORTED)
        return "it cannot take a method-scoped grant (a Qt plugin built before them)";
    if (status == LP_ERR_UNSUPPORTED)
        return "this module was not granted token_delivery, so it cannot push tokens";
    return "the token could not be pushed to it";
}

bool isOperatorKey(const std::string& caller)
{
    return caller.rfind("@op:", 0) == 0;
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

std::string CapabilityAuthority::Grant::json() const
{
    if (kind == Kind::All) return "\"*\"";
    nlohmann::json list = nlohmann::json::array();
    if (kind == Kind::Methods)
        for (const std::string& method : methods) list.push_back(method);
    return list.dump();
}

void CapabilityAuthority::setTokenPush(TokenPush push)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tokenPush = std::move(push);
}

std::string CapabilityAuthority::admit(const std::string& name, const std::string& kind,
                                       uint64_t& generation, bool pending)
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
    m_identities[name] = Identity{credential, kind, generation, !pending};
    return credential;
}

bool CapabilityAuthority::openTarget(const std::string& name)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_identities.find(name);
    if (it == m_identities.end()) return false;
    it->second.open = true;
    return true;
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
                revocations.push_back({target, caller, digestOf(pair->second.token)});
            pair = m_pairs.erase(pair);
        }
        m_pairChanged.notify_all();
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
    return it == m_pairs.end() ? std::string{} : it->second.token;
}

void CapabilityAuthority::recordPair(const std::string& caller, const std::string& target,
                                     const std::string& token)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pairs[{caller, target}] = Pair{token, Grant::all(), false};
}

void CapabilityAuthority::forgetPair(const std::string& caller, const std::string& target)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_pairs.erase({caller, target});
    m_pairChanged.notify_all();
}

// Lists give each named caller every method; objects map a caller to "*", a method
// list, or [] (nothing). Anything else refuses the whole document.
std::optional<std::map<std::string, CapabilityAuthority::Rule>>
CapabilityAuthority::parseRules(const std::string& text, bool objects) const
{
    const nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
    if (!doc.is_object()) return std::nullopt;
    std::map<std::string, Rule> rules;
    for (const auto& [target, callers] : doc.items()) {
        if (target.empty()) return std::nullopt;
        Rule& rule = rules[target];
        if (callers.is_array()) {
            for (const auto& caller : callers) {
                if (!caller.is_string() || caller.get<std::string>().empty()) return std::nullopt;
                rule[caller.get<std::string>()] = Grant::all();
            }
            continue;
        }
        if (!objects || !callers.is_object()) return std::nullopt;
        for (const auto& [caller, value] : callers.items()) {
            if (caller.empty()) return std::nullopt;
            Grant grant;
            if (value.is_string() && value.get<std::string>() == "*") {
                grant = Grant::all();
            } else if (value.is_array()) {
                grant.kind = value.empty() ? Grant::Kind::None : Grant::Kind::Methods;
                for (const auto& method : value) {
                    if (!method.is_string()) return std::nullopt;
                    const std::string name = method.get<std::string>();
                    if (name.empty() || name == "*" || !grant.methods.insert(name).second)
                        return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
            rule[caller] = std::move(grant);
        }
    }
    return rules;
}

// A pair the new rules deny, or grant differently, stops working now.
void CapabilityAuthority::replaceRules(std::map<std::string, Rule> rules, bool operatorsBound)
{
    std::vector<Revocation> revocations;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_rules = std::move(rules);
        m_operatorsBound = operatorsBound;
        for (auto pair = m_pairs.begin(); pair != m_pairs.end();) {
            const auto& [caller, target] = pair->first;
            if (evaluate(caller, target) == pair->second.grant) {
                ++pair;
                continue;
            }
            if (m_identities.count(target))
                revocations.push_back({target, caller, digestOf(pair->second.token)});
            pair = m_pairs.erase(pair);
        }
        m_pairChanged.notify_all();
    }
    queueRevocations(std::move(revocations));
}

bool CapabilityAuthority::setRestrictions(const std::string& text)
{
    auto rules = parseRules(text, false);
    if (!rules) return false;
    replaceRules(std::move(*rules), false);
    return true;
}

bool CapabilityAuthority::setAccessRules(const std::string& text)
{
    auto rules = parseRules(text, true);
    if (!rules) return false;
    replaceRules(std::move(*rules), true);
    return true;
}

// An exact caller wins, then "@op:*" for an operator or "*" for anyone else.
CapabilityAuthority::Grant CapabilityAuthority::evaluate(const std::string& caller,
                                                         const std::string& target) const
{
    const auto rule = m_rules.find(target);
    if (rule == m_rules.end()) return Grant::all();
    const bool op = isOperatorKey(caller);
    if (op && !m_operatorsBound) return Grant::all();
    if (const auto exact = rule->second.find(caller); exact != rule->second.end())
        return exact->second;
    const auto wildcard = rule->second.find(op ? "@op:*" : "*");
    return wildcard == rule->second.end() ? Grant{} : wildcard->second;
}

CapabilityAuthority::Grant CapabilityAuthority::grantFor(const std::string& caller,
                                                         const std::string& target) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return evaluate(caller, target);
}

bool CapabilityAuthority::allows(const std::string& caller, const std::string& target) const
{
    return grantFor(caller, target).kind != Grant::Kind::None;
}

std::string CapabilityAuthority::issuePair(const std::string& caller, const std::string& target,
                                           std::string* why)
{
    const auto refuse = [why](std::string reason) {
        if (why) *why = std::move(reason);
        return std::string{};
    };
    std::vector<Revocation> revocations;
    std::unique_lock<std::mutex> lock(m_mutex);
    Grant grant;
    std::string auth;
    uint64_t generation = 0;
    for (;;) {
        const auto identity = m_identities.find(target);
        if (identity == m_identities.end()) return refuse("the runtime has not admitted it");
        if (identity->second.kind != "module") return refuse("it calls, nothing calls it");
        if (!identity->second.open) return refuse("it is still loading");
        grant = evaluate(caller, target);
        if (grant.kind == Grant::Kind::None) return refuse("the access policy denies it");
        const auto pair = m_pairs.find({caller, target});
        if (pair == m_pairs.end()) {
            auth = identity->second.credential;
            generation = identity->second.generation;
            break;
        }
        if (pair->second.pushing) {
            m_pairChanged.wait(lock);
            continue;
        }
        if (pair->second.grant == grant) return pair->second.token;
        revocations.push_back({target, caller, digestOf(pair->second.token)});
        m_pairs.erase(pair);
    }
    // Recorded before the push, so a revocation or a new rule racing it finds it.
    const std::string token = mintToken();
    m_pairs[{caller, target}] = Pair{token, grant, true};
    const TokenPush push = m_tokenPush;
    lock.unlock();
    queueRevocations(std::move(revocations));
    revocations.clear();

    Push request{target, caller, token, auth, std::nullopt};
    if (grant.kind == Grant::Kind::Methods)
        request.scope = nlohmann::json{{"methods", grant.methods}}.dump();
    const int status = push ? push(request) : pushTokenToTarget(request);

    lock.lock();
    const auto pair = m_pairs.find({caller, target});
    const bool ours = pair != m_pairs.end() && pair->second.token == token;
    bool kept = false;
    if (status == LP_OK && ours) {
        const auto identity = m_identities.find(target);
        kept = identity != m_identities.end() && identity->second.generation == generation
            && evaluate(caller, target) == grant;
    }
    if (ours) {
        if (kept) pair->second.pushing = false;
        else m_pairs.erase(pair);
    }
    // Delivered but no longer wanted: withdraw it at the target, after the push.
    if (status == LP_OK && !kept && m_identities.count(target))
        revocations.push_back({target, caller, digestOf(token)});
    m_pairChanged.notify_all();
    lock.unlock();
    queueRevocations(std::move(revocations));
    if (status != LP_OK) return refuse(pushFailure(status));
    if (!kept) return refuse("it was withdrawn while its token was pushed");
    return token;
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

// The target learns the token as "@op:<op>", a key no module name can take; the
// same evaluation as requestModule decides it.
char* engineGrantOperatorPair(const char* op, const char* target)
{
    if (!op || !*op || !target) return nullptr;
    std::string why;
    const std::string key = std::string("@op:") + op;
    const std::string token = CapabilityAuthority::instance().issuePair(key, target, &why);
    if (token.empty()) {
        std::fprintf(stderr, "[capability_module] refusing operator %s -> %s: %s\n", op, target,
                     why.c_str());
        return nullptr;
    }
    return copy(token);
}

int engineSetRestrictions(const char* json)
{
    return json && CapabilityAuthority::instance().setRestrictions(json) ? 0 : -1;
}

void engineStringFree(char* value)
{
    std::free(value);
}

int engineSetAccessRules(const char* json)
{
    return json && CapabilityAuthority::instance().setAccessRules(json) ? 0 : -1;
}

char* engineGrantFor(const char* caller, const char* target)
{
    if (!caller || !target) return nullptr;
    return copy(CapabilityAuthority::instance().grantFor(caller, target).json());
}

char* engineAdmitPending(const char* name, const char* kind, unsigned long long* generation)
{
    if (!name || !kind || !generation) return nullptr;
    uint64_t admitted = 0;
    const std::string credential =
        CapabilityAuthority::instance().admit(name, kind, admitted, true);
    if (credential.empty()) return nullptr;
    *generation = admitted;
    return copy(credential);
}

int engineOpenTarget(const char* name)
{
    return name && CapabilityAuthority::instance().openTarget(name) ? 0 : -1;
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
    &engineSetAccessRules,
    &engineGrantFor,
    &engineAdmitPending,
    &engineOpenTarget,
};

} // namespace

extern "C" LOGOS_MODULE_IMPL_EXPORT const logos_capability_engine_v1* logos_module_capability_engine_v1()
{
    return &kEngine;
}
