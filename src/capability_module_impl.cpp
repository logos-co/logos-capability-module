#include "capability_module_impl.h"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <logos_host_services.h>
#include <logos_protocol.h>

#include <cstdio>

namespace {

// The minted value IS the auth token, so this is the one place entropy matters.
// Deliberately the SAME generator the host uses to mint each module's token
// (logos-liblogos module_manager.cpp), rather than a hand-rolled
// std::random_device formatter: boost seeds from the platform CSPRNG
// (/dev/urandom, BCryptGenRandom), whereas std::random_device is permitted to
// be DETERMINISTIC and historically was on MinGW — which is a live target here.
std::string mintToken()
{
    static boost::uuids::random_generator gen;
    return boost::uuids::to_string(gen());
}

// RAII for the per-target client. lp_client_destroy is safe from any thread and
// defers teardown to the owner thread when needed, so an early return cannot
// leak the handle.
class ClientHandle {
public:
    ClientHandle(const std::string& target, const std::string& origin)
        : m_c(lp_client_create(target.c_str(), origin.c_str(), nullptr, nullptr)) {}
    ~ClientHandle() { if (m_c) lp_client_destroy(m_c); }
    ClientHandle(const ClientHandle&) = delete;
    ClientHandle& operator=(const ClientHandle&) = delete;

    lp_client* get() const { return m_c; }
    explicit operator bool() const { return m_c != nullptr; }

private:
    lp_client* m_c = nullptr;
};

void warn(const char* fmt, const std::string& a, const std::string& b = {})
{
    std::fprintf(stderr, fmt, a.c_str(), b.c_str());
}

// A module that calls out from its own initializer has not published its
// source yet, so this one grant can be unsatisfiable. Waiting the protocol
// default (20s) there would blow every startup deadline downstream — the
// standalone app gives a ui-host 10s to report ready — and turn one
// unreachable module into a dead UI. Fail fast instead: the caller gets no
// token and a clear reason, and the rest of startup keeps moving.
constexpr int kTokenPushTimeoutMs = 3000;

} // namespace

std::string CapabilityModuleImpl::requestModule(const std::string& fromModuleName,
                                                const std::string& moduleName)
{
    if (fromModuleName.empty() || moduleName.empty()) {
        warn("[capability_module] rejecting empty module name (from='%s' target='%s')\n",
             fromModuleName, moduleName);
        return {};
    }

    // Known-caller gate. The requesting identity must be one this image has a
    // token for; fail closed on an unknown name rather than mint a token for a
    // self-asserted identity that was never loaded.
    //
    // This reads the token REGISTRY, so it is the call that makes the
    // "token_registry" grant load-bearing: ungranted, tokenKeys() returns empty
    // and every request is refused. That is the correct fail-closed direction,
    // but it means a missing grant looks exactly like "nothing is loaded" —
    // hence the explicit status check rather than an `empty()` test.
    logos::host::Status keysStatus;
    const std::vector<std::string> known = logos::host::tokenKeys(&keysStatus);
    if (keysStatus.ungranted()) {
        warn("[capability_module] REFUSING '%s': this module was not granted the "
             "token_registry host service, so it cannot verify any caller\n",
             fromModuleName);
        return {};
    }
    bool callerKnown = false;
    for (const std::string& k : known) {
        if (k == fromModuleName) { callerKnown = true; break; }
    }
    if (!callerKnown) {
        warn("[capability_module] rejecting request from unknown module identity '%s' "
             "- no token registered for it\n", fromModuleName);
        return {};
    }

    // Known-target gate: no token for the target means it is not loaded. Don't
    // hand back a token the target would reject anyway.
    const std::string moduleToken = logos::host::tokenFor(moduleName);
    if (moduleToken.empty()) {
        warn("[capability_module] rejecting request for unknown target '%s' "
             "- no token registered for it\n", moduleName);
        return {};
    }

    // Access-policy gate.
    //
    // TODO(access-policy): still fail-OPEN — a target with no registered
    // restriction is unrestricted. Intentional for back-compat during rollout;
    // the end state is deny-by-default once every deployment ships a policy.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_restrictions.find(moduleName);
        if (it != m_restrictions.end() && it->second.count(fromModuleName) == 0) {
            warn("[capability_module] access policy denies '%s' -> '%s'\n",
                 fromModuleName, moduleName);
            return {};
        }
    }

    const std::string authToken = mintToken();

    ClientHandle client(moduleName, "capability_module");
    if (!client) {
        warn("[capability_module] could not create a client for target '%s'\n", moduleName);
        return {};
    }

    // Deliver the token for the REQUESTER to the TARGET.
    //
    // The argument order is the trap here, so spell it out: authenticate with
    // the TARGET's own token, `originModule` is the TARGET (the module being
    // told), and `moduleName` is the REQUESTER (the module the token is FOR).
    // Swapping the last two still compiles and still returns an ok-shaped
    // status; it just tells the wrong module about the wrong token.
    const logos::host::Status pushed = logos::host::informModuleTokenTo(
        client.get(),
        /*authToken=*/moduleToken,
        /*originModule=*/moduleName,
        /*moduleName=*/fromModuleName,
        /*token=*/authToken,
        kTokenPushTimeoutMs);

    if (!pushed) {
        if (pushed.ungranted()) {
            warn("[capability_module] REFUSING '%s': this module was not granted the "
                 "token_delivery host service, so it cannot push tokens\n", moduleName);
        } else {
            warn("[capability_module] failed to inform '%s' about the token for '%s'\n",
                 moduleName, fromModuleName);
        }
        return {};
    }

    return authToken;
}

bool CapabilityModuleImpl::registerRestriction(const std::string& authToken,
                                               const std::string& targetModule,
                                               const std::vector<std::string>& allowedCallers)
{
    // Trusted-channel gate: only core (or this module) may rewrite the policy.
    // Both hold this module's auth token; a peer knows only its own. The
    // generic authorization that fronts this method accepts ANY issued token,
    // which would otherwise let any module rewrite the policy.
    //
    // constantTimeEquals, not ==: comparing a secret with == leaks the length
    // of the matching prefix through timing.
    const std::string coreToken = logos::host::tokenFor("core");
    const std::string capToken  = logos::host::tokenFor("capability_module");
    const bool callerIsTrusted =
        (!coreToken.empty() && logos::host::constantTimeEquals(authToken, coreToken)) ||
        (!capToken.empty()  && logos::host::constantTimeEquals(authToken, capToken));
    if (authToken.empty() || !callerIsTrusted) {
        warn("[capability_module] rejecting restriction for '%s' - caller is not the "
             "trusted core channel\n", targetModule);
        return false;
    }

    if (targetModule.empty()) {
        warn("[capability_module] rejecting empty target module%s\n", std::string());
        return false;
    }

    // Overwrite any previous restriction — core is the single source of truth
    // and re-registers the full set each boot.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_restrictions[targetModule] =
            std::set<std::string>(allowedCallers.begin(), allowedCallers.end());
    }
    return true;
}
