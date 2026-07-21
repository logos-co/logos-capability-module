#include "capability_module_impl.h"

#include <algorithm>
#include <random>

namespace {

// Length-independent constant-time comparison (ported from the Qt version to
// std::string): compare over the longer length and fold any length difference
// into the result, so neither a correct prefix nor the secret's length leaks
// through timing.
bool constantTimeEquals(const std::string& a, const std::string& b)
{
    const std::size_t n = std::max(a.size(), b.size());
    unsigned diff = static_cast<unsigned>(a.size() ^ b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
        const unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
        diff |= static_cast<unsigned>(ca ^ cb);
    }
    return diff == 0;
}

// Qt-free opaque token: 128 bits of OS entropy as lowercase hex. Replaces
// QUuid::createUuid(); a capability token only needs to be unique and
// unguessable, not RFC-4122-formatted.
std::string mintToken()
{
    std::random_device rd;
    static const char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (int i = 0; i < 32; ++i)
        s.push_back(kHex[rd() & 0xF]);
    return s;
}

} // namespace

std::string CapabilityModuleImpl::requestModule(const std::string& fromModuleName,
                                                const std::string& moduleName)
{
    if (fromModuleName.empty() || moduleName.empty())
        return {};

    // Known-caller gate: the requesting identity must be a module the host has a
    // token for (i.e. actually loaded). Fail closed on an unknown name rather
    // than mint a token for a self-asserted identity that was never loaded. A
    // non-empty stored token doubles as "this module is known".
    if (getToken(fromModuleName).empty())
        return {};

    // Known-target gate: no target token means the target is not loaded /
    // unknown. Don't hand back a token the target would reject anyway.
    const std::string moduleToken = getToken(moduleName);
    if (moduleToken.empty())
        return {};

    // Access-policy gate: if core registered a restriction for this target, only
    // the listed callers may obtain a token. A target with no registered
    // restriction is unrestricted (back-compat; fail-open — see the note in
    // registerRestriction / the original module's TODO).
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_restrictions.find(moduleName);
        if (it != m_restrictions.end() && it->second.find(fromModuleName) == it->second.end())
            return {};
    }

    const std::string newToken = mintToken();

    // Inform the target of the caller's new token (authenticated with the
    // target's own token). The host bridge acquires the target's client on its
    // owner thread and marshals the call, so this is safe from the multi worker.
    if (!informModuleToken(moduleName, moduleToken, fromModuleName, newToken))
        return {};

    return newToken;
}

bool CapabilityModuleImpl::registerRestriction(const std::string& authToken,
                                               const std::string& targetModule,
                                               const std::vector<std::string>& allowedCallers)
{
    // Trusted-channel gate: only core (or capability_module itself) may register
    // restrictions. Both hold capability_module's / core's auth token; a peer
    // module only knows its own token and so cannot forge this.
    const std::string coreToken = getToken("core");
    const std::string capToken  = getToken("capability_module");
    const bool callerIsTrusted =
        (!coreToken.empty() && constantTimeEquals(authToken, coreToken)) ||
        (!capToken.empty()  && constantTimeEquals(authToken, capToken));
    if (authToken.empty() || !callerIsTrusted)
        return false;

    if (targetModule.empty())
        return false;

    // Overwrite any previous restriction for this target — core is the single
    // source of truth and re-registers the full set each boot.
    std::lock_guard<std::mutex> lock(m_mutex);
    m_restrictions[targetModule] =
        std::unordered_set<std::string>(allowedCallers.begin(), allowedCallers.end());
    return true;
}
