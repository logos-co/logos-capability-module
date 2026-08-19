# Logos Capability Module Specification

note: This document is a living document describing the current state of the capability module.

## Table of Contents

- [1. Overview and Goals](#1-overview-and-goals)
- [2. Architecture](#2-architecture)
  - [2.1 Role in Logos](#21-role-in-logos)
  - [2.2 Tokens and Authentication](#22-tokens-and-authentication)
- [3. API Description](#3-api-description)
  - [3.1 Capability Module Interface](#31-capability-module-interface)
- [4. Implementation](#4-implementation)
  - [4.1 Module Structure](#41-module-structure)
  - [4.2 Responsibilities](#42-responsibilities)
  - [4.3 Token Flow](#43-token-flow)
- [5. Usage](#5-usage)
  - [5.1 Remote API Usage](#51-remote-api-usage)
  - [5.2 Metadata](#52-metadata)

## 1. Overview and Goals

The Capability Module is the broker that coordinates authentication tokens between Logos modules. When one module wants to call another, it requests a capability token instead of bypassing auth. The capability module issues a token, informs the target module about it, and returns the token to the requester so both sides share the same secret.

## 2. Architecture

### 2.1 Role in Logos

- Runs as a standard Logos plugin loaded by the core.
- Implemented as a `LogosModuleContext` subclass. The impl is **Qt-free** — zero Qt types in its own translation units; the contract is derived from the impl header and the Qt plugin glue is generated at build time.
- Exposes a single RPC surface (`requestModule`) so other modules or apps can obtain permission to call a target module.
- Reaches the token store and the token-delivery path through `logos_host_services.h`, the C++ veneer over the privileged C ABI (`lp_token_keys`, `lp_inform_module_token_to`). Those are gated by the host-services grant, which the host pushes into this module's image — the host decides who gets it, and `hostServicesFor()` names `capability_module` alone.

### 2.2 Tokens and Authentication

- Qt Remote Objects provides no built-in auth. The capability module issues per-pair tokens for inter-module calls.
- Tokens are stored in the shared `TokenManager` keyed by module name.
- When issuing a token, the capability module uses its own client to inform the target module of the new token so that the target's `ModuleProxy` can validate subsequent calls.

## 3. API Description

### 3.1 Capability Module Interface

The impl class `CapabilityModuleImpl` derives `LogosModuleContext`. Its public methods **are** the
API — there is no dispatch marker; the generator derives the contract from the header:

| Method | Purpose |
|--------|---------|
| `requestModule(fromModuleName, moduleName) → std::string` | Generates a fresh token for `fromModuleName` to call `moduleName`, informs the target of the token, and returns it to the caller. Returns an **empty string** on any refusal — unknown caller, unknown target, policy denial, or an unreachable target. |
| `registerRestriction(authToken, targetModule, allowedCallers) → bool` | Records an allowed-caller list for `targetModule`. Refused unless `authToken` is the trusted core/capability channel. |

Typed events would be declared under a `logos_events:` section. The module currently emits none.

## 4. Implementation

### 4.1 Module Structure

```
logos-capability-module/
├── src/
│   ├── capability_module_impl.{h,cpp}   # CapabilityModuleImpl : LogosModuleContext — plain
│   │                                    # public methods; no Qt, no dispatch macros
│   └── capability_module.lidl           # DEAD: the hand-committed contract from the
│                                        # `interface: "legacy"` era. Nothing reads it now —
│                                        # the contract in use is generated (step 1 below)
├── tests/                               # Unit tests via logos-test-framework
│   ├── CMakeLists.txt
│   ├── main.cpp
│   └── test_capability_module.cpp
├── metadata.json                        # interface: universal + codegen{impl_class, impl_header}
├── flake.nix                            # mkLogosModule call
├── CMakeLists.txt                       # logos_module() call
└── docs/                                # This document
```

Nothing under `generated_code/` is checked in. As an `interface: "universal"` module the
builder runs three steps at build time:

| step | produces |
|---|---|
| `logos-cpp-generator --header-to-lidl` | `capability_module.lidl` — the contract, derived from the impl header |
| `logos-qt-host-generator --backend cdylib` | `capability_module_cdylib_glue.{h,cpp}` — the Qt plugin glue over the module-impl C ABI |
| `logos-cpp-generator --lidl --backend cdylib` | `capability_module_module_impl.cpp` — the Qt-free C-ABI export wrapper, plus `capability_module_types.h` |

There is no hand-written plugin loader and no `logos_provider_dispatch.cpp`. Both belonged to
the `interface: "provider"` path (`logos-cpp-generator --provider-header`, `LOGOS_METHOD`
dispatch, a `LogosProviderBase` subclass), which was removed — a module is a plain shared
library now, and making one a Qt plugin is a downstream hosting step.

### 4.2 Responsibilities

- **Token issuance for inter-module calls**: On `requestModule`, mint a UUID token for the
  caller/target pair with `boost::uuids::random_generator` — deliberately the same
  CSPRNG-seeded generator the host uses, because the minted value **is** the auth token.
- **Inform targets of new tokens**: `logos::host::informModuleTokenTo()`, over an `lp_client`
  created for the target, tells that module about the new token. (Was
  `LogosAPIClient::informModuleToken_module` — `LogosAPIClient` is a Qt type this Qt-free
  impl cannot use.) It authenticates with `tokenFor(target)` — the token this image holds
  under the **target's** name — not with anything belonging to the requester.
- **Central coordination**: requests are **not** always granted. Three gates run before a
  token is minted — the caller must be a module this image holds a token for (this reads the
  token registry, so an ungranted `token_registry` refuses *every* request), the target must
  likewise be known, and a target with a registered restriction must list the caller. A
  target with **no** registered restriction is still unrestricted: that last gate is
  fail-OPEN by design during rollout (`TODO(access-policy)` in the impl), with
  deny-by-default as the end state.

### 4.3 Token Flow

1. Caller invokes `requestModule(from, target)`.
2. Both names are checked: non-empty, `from` present in `logos::host::tokenKeys()`, `target`
   holding a token, and the access policy allowing the pair. Any refusal returns an empty
   string and nothing is minted.
3. The auth token used for the push comes from `logos::host::tokenFor(target)` — the token
   this image holds under the target's name. (Was a direct `TokenManager` lookup; the Qt-free
   impl goes through the `logos_host_services.h` veneer instead. Note `tokenFor` wraps
   `lp_token_get`, which is **not** gated — only enumeration via `lp_token_keys` is.)
4. It mints the UUID token, creates an `lp_client` for the target, and calls
   `logos::host::informModuleTokenTo(client, authToken = tokenFor(target),
   originModule = the target, moduleName = the REQUESTER, token = the new token, 3000 ms)`.
   The argument order is the trap: swapping the last two still compiles and still returns an
   ok-shaped status, while telling the wrong module about the wrong token. The 3 s timeout is
   deliberately shorter than the protocol default (20 s), so a module calling out from its own
   initializer fails fast instead of blowing downstream startup deadlines.
5. Returns the new token to the caller. Both sides now share the token for subsequent RPCs. If
   the push fails or times out, the caller gets an empty string instead.

## 5. Usage

### 5.1 Remote API Usage

Modules or apps call the capability module via Logos RPC (e.g., using generated wrappers or `LogosAPIClient`):

```cpp
// Using generated wrappers
LogosModules logos(api); // api is a LogosAPI* for your module/app
QString token = logos.capability_module.requestModule("chat_ui", "waku_module");
```

The returned token must be used by the caller when invoking methods on the target module; SDK clients attach it automatically.

### 5.2 Metadata

`metadata.json` fields:
- `name`: `capability_module`
- `version`: semantic version string
- `description`: describes token brokering/coordination
- `author`: module author/maintainer
- `type`: `core`
- `interface`: `universal` — the header-first cdylib path. With `codegen.impl_class` /
  `codegen.impl_header` it names the class the contract is derived from. Two earlier values:
  `provider` until 22e54ff (a `LogosProviderBase` + `LOGOS_METHOD` codegen path that no longer
  exists), then the default `legacy` — a handcrafted `Q_OBJECT` / `Q_INVOKABLE` Qt plugin —
  until fc39b1b.
- `codegen`: `impl_class` / `impl_header` — the class and header the contract is derived from
  (`CapabilityModuleImpl`, `src/capability_module_impl.h`)
- `host_services`: `["token_registry", "token_delivery"]` — the two privileges this module
  declares and the host grants, bound to its verified name. Ungranted, every gated call fails
  closed (see §2.1)
- `capabilities`: typically includes `module_coordination`, `permission_management`
- `dependencies`: usually none (bundled with core)
- `nix`: build configuration consumed by `logos-module-builder` (packages, external_libraries, cmake flags)
