#include "capability_module_impl.h"
#include "capability_authority.h"

#include <logos_caller.h>
#include <logos_protocol.h>

#include <cstdio>

namespace {

void warn(const char* fmt, const std::string& a, const std::string& b = {})
{
    std::fprintf(stderr, fmt, a.c_str(), b.c_str());
}

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

    // Only an admitted, open module can be a target, the access rules decide the
    // grant, and the pair's token is pushed to the target scoped to that grant.
    std::string why;
    const std::string token = CapabilityAuthority::instance().issuePair(callerName, moduleName, &why);
    if (token.empty())
        std::fprintf(stderr, "[capability_module] refusing '%s' -> '%s': %s\n",
                     callerName.c_str(), moduleName.c_str(), why.c_str());
    return token;
}

LogosShutdown CapabilityModuleImpl::aboutToUnload()
{
    CapabilityAuthority::instance().stopRevocations();
    return LogosShutdown::Synchronous;
}
