#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// capability_module — the trust root, as an ordinary universal module.
//
// It mints per-(caller, target) auth tokens and pushes them to the target, and
// it holds the access policy core registers. That needs two privileges no other
// module has: enumerating the token store, and delivering a token to an
// arbitrary module. It declares them in metadata.json:
//
//     "host_services": ["token_registry", "token_delivery"]
//
// and the HOST grants them, bound to this module's verified name. Ungranted,
// every gated call fails closed — and note that is not a partial degradation:
// the known-caller check below reads the token registry, so an ungranted
// capability_module refuses EVERY requestModule.
//
// No Qt: this is a plain C++ class the generator turns into a module. The Qt
// plugin it used to be reached TokenManager directly, which is exactly the
// ambient privilege the host-services grant replaces.
//
// NO trailing `// comments` on declaration lines (the parser needs a `;`).
// ─────────────────────────────────────────────────────────────────────────────

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <logos_module_context.h>

class CapabilityModuleImpl : public LogosModuleContext {
public:
    CapabilityModuleImpl() = default;
    ~CapabilityModuleImpl() = default;

    // Mint a token letting `fromModuleName` call `moduleName`, push it to the
    // target, and return it. Empty string on any refusal — an unknown caller,
    // an unknown target, a policy denial, or an unreachable target.
    std::string requestModule(const std::string& fromModuleName,
                              const std::string& moduleName);

    // Restrict `targetModule` to `allowedCallers`. Only core (or this module)
    // may call this; the check is a constant-time comparison against their
    // tokens. Re-registering a target replaces its previous set.
    bool registerRestriction(const std::string& authToken,
                             const std::string& targetModule,
                             const std::vector<std::string>& allowedCallers);

private:
    // target -> callers permitted to reach it. A target absent from the map is
    // unrestricted; see the fail-open note in the .cpp.
    //
    // Guarded because a universal module may be dispatched concurrently if it
    // ever declares concurrency:"multi", and because this is policy state — the
    // Qt original was implicitly serialised by the event loop, which is not a
    // property to inherit silently.
    std::map<std::string, std::set<std::string>> m_restrictions;
    mutable std::mutex m_mutex;
};
