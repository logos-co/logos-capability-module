#pragma once

// ─────────────────────────────────────────────────────────────────────────────
// capability_module — the token authority, as an ordinary universal module.
//
// The runtime admits every module, shell and presentation consumer through the
// engine interface (logos_capability_engine.h); this module mints and records
// their credentials. Its one dispatchable method, requestModule, mints a token
// for an admitted (caller, target) pair and pushes it to the target. Pushing a
// token AT another module is a privilege no other module has, declared in
// metadata.json:
//
//     "host_services": ["token_delivery"]
//
// and granted by the HOST. Ungranted, every push fails closed.
//
// No Qt: this is a plain C++ class the generator turns into a module.
//
// NO trailing `// comments` on declaration lines (the parser needs a `;`).
// ─────────────────────────────────────────────────────────────────────────────

#include <string>

#include <logos_module_context.h>

class CapabilityModuleImpl : public LogosModuleContext {
public:
    CapabilityModuleImpl() = default;
    ~CapabilityModuleImpl() = default;

    // Mint a token letting the RPC caller (logos::currentCaller) call
    // `moduleName`, push it to the target, and return it. `fromModuleName` is
    // leftover ABI and is not used for identity. Empty string on any refusal —
    // unnamed caller, a target the runtime has not admitted, policy denial, or
    // an unreachable target.
    std::string requestModule(const std::string& fromModuleName,
                              const std::string& moduleName);

    // Stops the revocation worker: nothing is pushed once the module goes.
    LogosShutdown aboutToUnload() override;
};
