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

The Capability Module is the runtime's token authority. liblogos loads it in-process and admits
every module, shell and presentation consumer (UI plugin) through its engine interface; the
module mints and records their credentials. When one module wants to call another, it asks
for a token (`requestModule`): the module mints one for the pair, pushes it to the target, and
returns it to the requester, so both sides share the same secret.

## 2. Architecture

### 2.1 Role in Logos

- Bundled with the runtime and loaded in-process, before anything else. liblogos refuses to run
  it anywhere else: without it the runtime loads nothing.
- Implemented as a `LogosModuleContext` subclass. The impl is **Qt-free** — zero Qt types in its
  own translation units; the contract is derived from the impl header.
- Two surfaces:
  - the **engine interface** (`logos_capability_engine.h`, exported as
    `logos_module_capability_engine_v1`, version 2): admit, retire, resolve a caller, a
    credential for the engine's own calls, operator pair tokens, and the access rules. Version 2
    appends `set_access_rules` (method grants), `grant_for`, `admit_pending` and
    `open_target`; version 1's `set_restrictions` keeps its grammar and meaning. Only the
    engine calls it, in-process; it is not part of the dispatch surface.
  - **`requestModule`**, the one dispatchable method, for modules and apps.
- Pushes tokens to targets with `lp_inform_module_token_to`, `lp_inform_scoped_module_token_to`
  (a method-list grant) and `lp_revoke_module_token_to`. Those are gated by the
  `token_delivery` host service, which the host grants this module alone.

### 2.2 Tokens and Authentication

- Every credential comes from here. An admission's credential reaches its holder through the
  runtime: on stdin for a hosted module, in-process for the rest.
- A pair token is minted once per (caller, target) while both stay admitted, and a repeat
  request returns the same one. The raw token lives in memory only.
- Retiring an identity revokes the tokens it holds at other modules; new rules revoke the pairs
  they deny or grant differently, and leave the others, operators' included. Revocations name a
  token by its digest (`lp_token_digest`) and are pushed by one worker the module owns.

## 3. API Description

### 3.1 Capability Module Interface

The impl class `CapabilityModuleImpl` derives `LogosModuleContext`. Its public methods **are** the
API — there is no dispatch marker; the generator derives the contract from the header:

| Method | Purpose |
|--------|---------|
| `requestModule(fromModuleName, moduleName) → std::string` | The token the **RPC caller** (`logos::currentCaller`) presents to call `moduleName`: minted and pushed to the target on first request, the same one while the pair stays valid. `fromModuleName` is leftover ABI and is not used for identity. Returns an **empty string** on any refusal — unnamed caller, a target the runtime has not admitted, policy denial, or an unreachable target. |

Typed events would be declared under a `logos_events:` section. The module currently emits none.

## 4. Implementation

### 4.1 Module Structure

```
logos-capability-module/
├── src/
│   ├── capability_module_impl.{h,cpp}   # CapabilityModuleImpl : LogosModuleContext — requestModule
│   ├── capability_authority.{h,cpp}     # the store of record, behind the engine interface
│   └── logos_capability_engine.h        # the engine interface
├── tests/                               # Unit tests via logos-test-framework
│   ├── CMakeLists.txt
│   ├── main.cpp
│   ├── test_capability_authority.cpp
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

- **Admission**: the engine admits each identity with a kind (`module`, `shell`, `presentation`)
  and gets its credential and an admission generation; retiring names that generation, so a
  late retire cannot end a newer admission.
- **Token issuance for inter-module calls**: a pair token is minted with
  `boost::uuids::random_generator`, which seeds from the platform CSPRNG — the minted value
  **is** the auth token.
- **Inform targets of new tokens**: over an `lp_client` created for the target, the pair's token
  is pushed with the **target's** own credential, which only this module and the target hold.
  A method-list grant is pushed scoped; a target that cannot take that (a Qt plugin built
  before method scopes) is refused, never given the token unscoped.
- **Central coordination**: requests are **not** always granted. Identity is
  `logos::currentCaller()`, not `fromModuleName`. The target must be admitted, and not a
  consumer-only identity (a shell or UI plugin), and it must be open: an admission from
  `admit_pending` takes no pairs until `open_target`. The access rules decide the grant:
  - a rule lists callers (every method), or maps callers to `"*"`, a method list, or `[]`
    (none). Callers are names, `@op:<name>`, `@op:*` (any operator) and `*` (any other caller);
  - an exact caller wins, then `@op:*` for an operator or `*` for anyone else; entries never
    merge. Operators are bound only by version 2 rules (`set_access_rules`);
  - a target with **no** rule is unrestricted: that gate is fail-OPEN by design during rollout
    (the runtime's `enforce` mode writes a rule for every loaded module).

### 4.3 Token Flow

1. Caller invokes `requestModule(from, target)`. `from` is leftover ABI.
2. The dispatch must carry a named caller (`logos::currentCaller`: host → `core`, or a module
   name). `target` must be admitted, and the access policy must allow the caller. Any refusal
   returns an empty string and nothing is minted.
3. If the pair already holds a token under the same grant, that token is returned. A request
   for a pair whose push is in flight waits for it: one push per pair at a time.
4. Otherwise it mints one, records the pair with its grant, and pushes it to the target
   (authenticated with the target's credential, `originModule` = the target, `moduleName` =
   the REQUESTER), scoped when the grant is a method list. The 3 s timeout is deliberately
   shorter than the protocol default (20 s), so a module calling out from its own initializer
   fails fast instead of blowing downstream startup deadlines.
5. After the push it checks the pair is still wanted: still on record, its target the same
   admission, and the same grant. If so, the token is returned; if a rule or a retirement
   overtook the push, the token is revoked at the target and the caller gets an empty string.
   A failed push forgets the pair.

## 5. Usage

### 5.1 Remote API Usage

Modules or apps call the capability module via Logos RPC (e.g., using generated wrappers or `LogosAPIClient`):

```cpp
// Using generated wrappers
LogosModules logos(api); // api is a LogosAPI* for your module/app
QString token = logos.capability_module.requestModule("", "waku_module");
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
- `host_services`: `["token_delivery"]` — the privilege this module declares and the host grants,
  bound to its verified name. Ungranted, every push fails closed (see §2.1)
- `capabilities`: typically includes `module_coordination`, `permission_management`
- `dependencies`: none (bundled with the runtime)
- `nix`: build configuration consumed by `logos-module-builder` (packages, external_libraries, cmake flags)
