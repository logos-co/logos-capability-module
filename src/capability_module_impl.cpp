#include "capability_module_impl.h"
#include "capability_authority.h"

#include <logos_caller.h>
#include <logos_host_services.h>
#include <logos_protocol.h>

#include <cstdio>

namespace {

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
    // Target emptiness is checked first so a missing name cannot be papered
    // over by a well-formed caller identity (or vice versa).
    if (moduleName.empty()) {
        warn("[capability_module] rejecting empty target module name (from='%s')\n",
             fromModuleName);
        return {};
    }

    // Identity comes from the RPC caller document the host pushed into this
    // image (logos_module_set_call_caller / logos::currentCaller), not from
    // `fromModuleName`. That argument is leftover ABI: any loaded allowlisted
    // name could be written there by the caller. Host maps to "core" (rule 5:
    // the host arm carries no name). Unnamed / unknown / derived / operator
    // refuse — those are not module identities this method can mint for.
    const logos::LogosCaller caller = logos::currentCaller();
    std::string callerName;
    if (caller.isHost()) {
        callerName = "core";
    } else if (caller.isModule() && !caller.name.empty()) {
        callerName = caller.name;
    } else {
        warn("[capability_module] rejecting request for '%s': no named caller on "
             "this dispatch (fromModuleName='%s')\n",
             moduleName, fromModuleName);
        return {};
    }
    if (!fromModuleName.empty() && fromModuleName != callerName) {
        warn("[capability_module] ignoring leftover fromModuleName='%s' "
             "(token-bound caller is '%s')\n",
             fromModuleName, callerName);
    }

    // Only an admitted target can be one: its credential authenticates the push
    // below, and nothing else knows it.
    CapabilityAuthority& authority = CapabilityAuthority::instance();
    const std::string moduleToken = authority.credentialFor(moduleName);
    if (moduleToken.empty()) {
        warn("[capability_module] rejecting request for '%s': the runtime has not "
             "admitted it (from '%s')\n", moduleName, callerName);
        return {};
    }
    if (authority.isConsumerOnly(moduleName)) {
        warn("[capability_module] rejecting request for '%s': it calls, nothing calls it "
             "(from '%s')\n", moduleName, callerName);
        return {};
    }

    // Access-policy gate, fed by the runtime through the engine interface.
    //
    // TODO(access-policy): still fail-OPEN — a target with no restriction is
    // unrestricted. Intentional for back-compat during rollout; the end state
    // is deny-by-default once every deployment ships a policy.
    if (!authority.allows(callerName, moduleName)) {
        warn("[capability_module] access policy denies '%s' -> '%s'\n", callerName, moduleName);
        return {};
    }

    // One token per pair while both are on record: a second client stack of the
    // same identity gets it again instead of overwriting the first's. Retiring
    // either side forgets it.
    if (std::string existing = authority.pairToken(callerName, moduleName); !existing.empty())
        return existing;

    const std::string authToken = CapabilityAuthority::mintToken();
    // Recorded before the push, so a revocation racing it can find it.
    authority.recordPair(callerName, moduleName, authToken);

    ClientHandle client(moduleName, "capability_module");
    if (!client) {
        authority.forgetPair(callerName, moduleName);
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
        /*moduleName=*/callerName,
        /*token=*/authToken,
        kTokenPushTimeoutMs);

    if (!pushed) {
        authority.forgetPair(callerName, moduleName);
        if (pushed.ungranted()) {
            warn("[capability_module] REFUSING '%s': this module was not granted the "
                 "token_delivery host service, so it cannot push tokens\n", moduleName);
        } else {
            warn("[capability_module] failed to inform '%s' about the token for '%s'\n",
                 moduleName, callerName);
        }
        return {};
    }

    return authToken;
}

LogosShutdown CapabilityModuleImpl::aboutToUnload()
{
    CapabilityAuthority::instance().stopRevocations();
    return LogosShutdown::Synchronous;
}
