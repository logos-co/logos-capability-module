# Composing Two Modules Through This Capability Module

`logos-capability-module` is the `core` module the host loads first: it is the
permission broker every other module is routed through. When `logoscore` loads
a module, and when one module calls another over IPC, the request passes the
capability layer this module implements. So the sharpest test of a change here
is not to call the capability module directly — it is to put it underneath a
**real cross-module conversation** and confirm that conversation still works.

That is exactly what this doc-test does. It builds the `logoscore` runtime with
**this capability-module commit** wired in as the broker, then runs two ordinary
modules on top of it — one calling the other across the process boundary —
through every composition path the SDK offers:

1. Create `greeter_module`, a small **callee** with a couple of methods
   (`greet`, `addInts`, `greetCount`) and a `greeted` event.
2. Create `orchestrator_module`, a **caller** that declares `greeter_module`
   as a dependency and composes it through the generated
   `modules().greeter_module` wrapper — synchronously, asynchronously, and by
   subscribing to its event.
3. Build both modules' `.lgx` packages (against the latest published SDK — they
   are the payload, not the unit under test).
4. Build `logoscore` **with `logos-capability-module` pinned to the commit under
   test**, install both modules, load them together, and call the
   orchestrator's methods — each of which loads, authorises, and calls across
   the capability layer this commit provides.

Because every `load-module` and every cross-module `call` is mediated by the
capability module built from the commit under test, a green run is real
evidence that this change keeps module loading and inter-module composition —
the things the capability layer gates — working end to end.

**What you'll build:** Two modules — a `greeter_module` callee and an `orchestrator_module` caller — run together in a `logoscore` whose capability broker is built from this commit, with the caller driving the callee over IPC.

**What you'll learn:**

- How the capability module sits under every module load and every cross-module call
- How one module declares another as a dependency (`metadata.json` + `flake.nix` input)
- How the SDK generates a typed `modules().<dep>` wrapper with sync, async, and event APIs
- How to build `logoscore` with a specific `logos-capability-module` commit pinned across its closure
- How to load two modules in `logoscore` and chain calls so the caller drives the callee through the capability layer

## Prerequisites

- **Nix** with flakes enabled. Install from [nixos.org](https://nixos.org/download.html), then enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

Verify: `nix flake --help >/dev/null 2>&1 && echo "Flakes enabled"`

- **git** — nix flakes only see files tracked by git.
- A Linux or macOS machine.

---

## Step 1: Create the callee: greeter_module

`greeter_module` is an ordinary `core` module written in the pure-C++
(`interface: universal`) style: you write one plain class, and the builder
generates the Qt plugin glue. Every `public` method becomes callable over
IPC, and the `logos_events:` block declares an event other modules can
subscribe to. The greeter is a plain payload module — nothing about it
references the capability module; that layer is exercised when it is loaded
and called.

### 1.1 metadata.json

`dependencies` is empty — the greeter calls no one. `interface:
universal` selects the pure-C++ pattern.

```json
{
  "name": "greeter_module",
  "version": "1.0.0",
  "type": "core",
  "category": "general",
  "description": "A callee module: greets, counts greetings, and emits an event",
  "main": "greeter_module_plugin",
  "interface": "universal",
  "dependencies": [],

  "nix": {
    "packages": {
      "build": [],
      "runtime": []
    },
    "external_libraries": [],
    "cmake": {
      "find_packages": [],
      "extra_sources": []
    }
  }
}
```

### 1.2 CMakeLists.txt

For a universal module you list only your plain C++ sources; the generated glue is compiled automatically.

```cmake
cmake_minimum_required(VERSION 3.14)
project(GreeterModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found")
endif()

logos_module(
    NAME greeter_module
    SOURCES
        src/greeter_module_impl.h
        src/greeter_module_impl.cpp
)
```

### 1.3 flake.nix

A minimal flake that hands every input to `mkLogosModule`. The
`` on the builder URL is pinned by the doc-test runner; with no
pin it falls back to the latest published `logos-module-builder`.

```nix
{
  description = "Greeter core module - a callee for the composition doc-test";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
```

### 1.4 src/greeter_module_impl.h — the class

Plain C++ inheriting `LogosModuleContext`. The `///` doc comments
become each method's description; the `logos_events:` block declares
the `greeted` event (the token expands to `public` under a normal
compile, and the generator emits the event body).

```cpp
#pragma once

#include <cstdint>
#include <string>

#include <logos_module_context.h>  // LogosModuleContext base + logos_events

// A simple callee module. The orchestrator composes these methods over
// IPC. It also emits a `greeted` event so the caller can exercise a
// typed event subscription.
class GreeterModuleImpl : public LogosModuleContext {
public:
    GreeterModuleImpl() = default;
    ~GreeterModuleImpl() = default;

    /// Returns a greeting for the given name.
    std::string greet(const std::string& name);

    /// Adds two integers and returns the sum.
    int64_t addInts(int64_t a, int64_t b);

    /// Returns how many times greet() has been called on this instance.
    int64_t greetCount() const;

    /// Greets the name and also emits a `greeted` event carrying it.
    void greetNotify(const std::string& name);

logos_events:
    /// Emitted by greetNotify() with the produced greeting string.
    void greeted(const std::string& greeting);

private:
    int64_t m_greetCount = 0;
};
```

### 1.5 src/greeter_module_impl.cpp — the implementation

Plain C++ — no Qt, no IPC plumbing. `greetNotify` fires the generated event.

```cpp
#include "greeter_module_impl.h"

std::string GreeterModuleImpl::greet(const std::string& name)
{
    ++m_greetCount;
    return "Hello, " + name + "!";
}

int64_t GreeterModuleImpl::addInts(int64_t a, int64_t b)
{
    return a + b;
}

int64_t GreeterModuleImpl::greetCount() const
{
    return m_greetCount;
}

void GreeterModuleImpl::greetNotify(const std::string& name)
{
    // Emit the event declared in logos_events:. When loaded by a host
    // this reaches every subscriber; constructed outside a host it is a
    // safe no-op.
    greeted("Hello, " + name + "!");
}
```

---

## Step 2: Create the caller: orchestrator_module

`orchestrator_module` declares `greeter_module` as a dependency. That one
line in `metadata.json` is what makes the builder run the SDK's code
generator over the greeter's exported interface and emit a typed
`modules().greeter_module` wrapper — with sync callers, async callers, and
event subscribers — that the orchestrator uses without any raw `LogosAPI`.
At runtime, the very first thing that wrapper does is ask the capability
layer for a token to reach `greeter_module`.

### 2.1 metadata.json — declare the dependency

The `dependencies` entry must match `greeter_module`'s own
`metadata.json` `name`.

```json
{
  "name": "orchestrator_module",
  "version": "1.0.0",
  "type": "core",
  "category": "general",
  "description": "A caller module: composes greeter_module via typed sync/async calls and an event subscription",
  "main": "orchestrator_module_plugin",
  "interface": "universal",
  "dependencies": ["greeter_module"],

  "nix": {
    "packages": {
      "build": [],
      "runtime": []
    },
    "external_libraries": [],
    "cmake": {
      "find_packages": [],
      "extra_sources": []
    }
  }
}
```

### 2.2 CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.14)
project(OrchestratorModulePlugin LANGUAGES CXX)

if(DEFINED ENV{LOGOS_MODULE_BUILDER_ROOT})
    include($ENV{LOGOS_MODULE_BUILDER_ROOT}/cmake/LogosModule.cmake)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LogosModule.cmake")
    include(cmake/LogosModule.cmake)
else()
    message(FATAL_ERROR "LogosModule.cmake not found")
endif()

logos_module(
    NAME orchestrator_module
    SOURCES
        src/orchestrator_module_impl.h
        src/orchestrator_module_impl.cpp
)
```

### 2.3 flake.nix — add the dependency input

Declare `greeter_module` as a flake input; the input name **must
match** the dependency name in `metadata.json`. The `path:` value is a
placeholder — we lock it to the real greeter checkout in the build step
with `--override-input` (Nix won't accept a relative `../` path written
directly into `flake.nix`).

```nix
{
  description = "Orchestrator core module - calls greeter_module";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";

    # The module this one depends on. Placeholder path — locked to the
    # real checkout in the build step via --override-input.
    greeter_module.url = "path:/path/to/your/greeter_module";
  };

  outputs = inputs@{ logos-module-builder, greeter_module, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
```

### 2.4 src/orchestrator_module_impl.h — the class

Three composition paths, all through `modules().greeter_module`:
`greetThrough`/`greetReport` (sync), `startAsyncGreet`/`asyncGreeting`
(async), and `subscribeGreeted`/`lastGreetedEvent` (event).

```cpp
#pragma once

#include <cstdint>
#include <string>

#include <logos_json.h>            // LogosMap
#include <logos_module_context.h>  // LogosModuleContext base + modules()

// A caller module. It does nothing on its own — it composes
// greeter_module through the typed modules().greeter_module wrapper the
// builder generates from the dependency declared in metadata.json.
class OrchestratorModuleImpl : public LogosModuleContext {
public:
    OrchestratorModuleImpl() = default;
    ~OrchestratorModuleImpl() = default;

    /// Calls greeter_module.greet(name) and returns its result verbatim.
    std::string greetThrough(const std::string& name);

    /// Composes several greeter_module calls into one map: a greeting,
    /// an integer sum, and the greeter's current greet count.
    LogosMap greetReport(const std::string& name, int64_t a, int64_t b);

    /// Fires greeter_module.greetAsync(name) asynchronously and returns
    /// "queued" immediately; the reply lands in a callback. Read it back
    /// with asyncGreeting().
    std::string startAsyncGreet(const std::string& name);

    /// The greeting delivered by startAsyncGreet()'s callback, or empty
    /// until it arrives.
    std::string asyncGreeting() const;

    /// Subscribes to greeter_module's `greeted` event with a typed
    /// callback. Returns "ok" once registered.
    std::string subscribeGreeted();

    /// The last greeting captured by the `greeted` subscription, or
    /// empty until the event fires.
    std::string lastGreetedEvent() const;

private:
    std::string m_asyncGreeting;
    std::string m_lastGreetedEvent;
    bool        m_subscribed = false;
};
```

### 2.5 src/orchestrator_module_impl.cpp — the implementation

The `.cpp` includes the generated `logos_sdk.h` (which defines
`LogosModules`) — that's why the cross-module calls live here and not in
the header the generator parses. Each method drives `greeter_module`
through the generated wrapper: `.greet(...)` (sync), `.greetAsync(...,
cb)` (async), `.onGreeted(cb)` (event).

```cpp
#include "orchestrator_module_impl.h"

// Generated at build time by logos-cpp-generator. Defines LogosModules
// with one std-typed accessor per metadata.json dependency — here
// greeter_module. Included only in the .cpp so the impl header the
// generator parses stays free of Qt and codegen types.
#include "logos_sdk.h"

std::string OrchestratorModuleImpl::greetThrough(const std::string& name)
{
    // The simplest cross-module round-trip: one typed sync call.
    return modules().greeter_module.greet(name);
}

LogosMap OrchestratorModuleImpl::greetReport(const std::string& name,
                                             int64_t a, int64_t b)
{
    // Three typed sync calls into greeter_module, composed into one map.
    auto& greeter = modules().greeter_module;
    LogosMap report;
    report["greeting"]   = greeter.greet(name);
    report["sum"]        = greeter.addInts(a, b);
    report["greetCount"] = greeter.greetCount();
    return report;
}

std::string OrchestratorModuleImpl::startAsyncGreet(const std::string& name)
{
    // The generated async overload returns immediately; the reply is
    // delivered to the callback on this module's event loop.
    modules().greeter_module.greetAsync(name, [this](const std::string& g) {
        m_asyncGreeting = g;
    });
    return "queued";
}

std::string OrchestratorModuleImpl::asyncGreeting() const
{
    return m_asyncGreeting;
}

std::string OrchestratorModuleImpl::subscribeGreeted()
{
    if (m_subscribed) return "ok";
    // Typed subscriber generated from greeter_module's logos_events:
    // greeted(const std::string&). The accessor is `on` + the
    // capitalized event name.
    m_subscribed = modules().greeter_module.onGreeted(
        [this](const std::string& greeting) {
            m_lastGreetedEvent = greeting;
        });
    return m_subscribed ? "ok" : "failed";
}

std::string OrchestratorModuleImpl::lastGreetedEvent() const
{
    return m_lastGreetedEvent;
}
```

---

## Step 3: Build both modules

Nix flakes only see files tracked by git, so initialise a repo in each
module first. Then build each module's `.lgx`. These two modules are the
**payload**, not the unit under test — they build against the latest
published SDK and builder. (What is pinned to the commit under test is the
capability module, wired into the runtime in the next section.)

### 3.1 Initialise git repos

The greeter is a dependency of the orchestrator, so both must be tracked.

```bash
(cd greeter_module && git init -q && git add -A)
(cd orchestrator_module && git init -q && git add -A)

```

### 3.2 Build the greeter's .lgx

The greeter has no module dependency, so its `#lgx` builds straight from
its own flake.

```bash
# From inside the greeter clone this is simply:
#   nix build '.#lgx'
nix build 'path:./greeter_module#lgx' -o greeter-lgx
```

The greeter package is under `./greeter-lgx/`:

```bash
ls greeter-lgx/*.lgx
```

### 3.3 Build the orchestrator's .lgx

The orchestrator pulls in `greeter_module` as a dependency, so we lock
that input to the local greeter checkout — the dependency wrapper the
generator emits is built from that same checkout.

```bash
nix build 'path:./orchestrator_module#lgx' \
  --override-input greeter_module 'path:./greeter_module' \
  -o orchestrator-lgx
```

The orchestrator package is under `./orchestrator-lgx/`:

```bash
ls orchestrator-lgx/*.lgx
```

---

## Step 4: Build the runtime with this capability module and install both modules

Build `logoscore` with `logos-capability-module` **pinned to the commit
under test**, then build `lgpm` and install both modules into a `./modules`
directory the daemon can scan.

`logos-capability-module` appears twice in the `logoscore` closure — as a
direct input of `logos-logoscore-cli` (the bundled `capability_module`
plugin the daemon loads at boot) and inside `logos-liblogos` (the runtime
that hosts it). Overriding both pins the whole capability layer to this
commit.

> Each override URL carries a `` placeholder the doc-test runner
> expands to a concrete ref: locally that is this `logos-capability-module`
> checkout's `HEAD` (see `run.sh`); in CI it is the commit being tested.
> With no pin it falls back to latest `master`.

### 4.1 Build logoscore with this capability module

```bash
nix build 'github:logos-co/logos-logoscore-cli' \
  --override-input logos-capability-module 'github:logos-co/logos-capability-module' \
  --override-input logos-liblogos/logos-capability-module 'github:logos-co/logos-capability-module' \
  --out-link ./logos
```

The build produces `logos/bin/logoscore` plus bundled runtime libraries
and a `logos/modules/` directory containing the `capability_module` built
from the commit under test — the broker every load and call goes through.

### 4.2 Build lgpm

```bash
nix build 'github:logos-co/logos-package-manager#cli' -o lgpm
```

### 4.3 Seed the modules directory with this capability module

Loading any module goes through the host's capability layer, so the
modules directory needs the `capability_module` that ships with the
`logoscore` we just built — i.e. the one built from this commit. Copy it
across first.

```bash
mkdir -p modules
cp -RL ./logos/modules/. ./modules/

```

### 4.4 Install the greeter

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file greeter-lgx/*.lgx
```

### 4.5 Install the orchestrator

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file orchestrator-lgx/*.lgx
```

### 4.6 Confirm all three modules are present

```bash
./lgpm/bin/lgpm --modules-dir ./modules list
```

---

## Step 5: Load both modules and drive the caller

Start `logoscore` in daemon mode (`-D`) — it keeps each module's process
alive between `call` commands, so an event subscription registered by one
call is still active when a later call triggers it, and an async reply
lands before the call that reads it. The daemon auto-loads the
`capability_module` (this commit) at boot; loading the two payload modules
and every cross-module call below is then mediated by it.

### 5.1 Start the daemon

```bash
logoscore -D -m ./modules > logs.txt &
```

```bash
sleep 3
```

### 5.2 Load the greeter (the dependency first)

```bash
logoscore load-module greeter_module
```

### 5.3 Load the orchestrator

```bash
logoscore load-module orchestrator_module
```

### 5.4 Confirm both report loaded

```bash
logoscore status
```

### 5.5 Synchronous cross-module call

`greetThrough(name)` forwards straight to `greeter_module.greet(name)`
and returns the result — one typed sync call across the process
boundary, authorised by the capability layer:

```bash
logoscore call orchestrator_module greetThrough World
```

### 5.6 Compose several calls into one result

`greetReport(name, a, b)` fans out to three greeter calls — `greet`,
`addInts`, and `greetCount` — and returns them as one map. The greeter
has now been greeted twice (once above, once here), so `greetCount` is
`2`:

```bash
logoscore call orchestrator_module greetReport Logos 3 5
```

### 5.7 Asynchronous cross-module call

`startAsyncGreet(name)` fires `greeter_module.greetAsync(name)` and
returns `"queued"` immediately. The reply arrives on the daemon's event
loop; the next call, `asyncGreeting()`, reads what the callback stashed:

```bash
logoscore call orchestrator_module startAsyncGreet Async
```

```bash
sleep 1
```

### 5.8 Read the async reply

```bash
logoscore call orchestrator_module asyncGreeting
```

### 5.9 Subscribe to the greeter's event

`subscribeGreeted()` registers a typed callback on `greeter_module`'s
`greeted` event. Then `greeter_module.greetNotify(...)` makes the
greeter emit it, and `lastGreetedEvent()` reads what the subscription
captured. Because the daemon keeps both modules loaded, the event fires
between the calls:

```bash
logoscore call orchestrator_module subscribeGreeted
```

### 5.10 Trigger the event from the greeter

```bash
logoscore call greeter_module greetNotify Events
```

```bash
sleep 1
```

### 5.11 Read the captured event payload

```bash
logoscore call orchestrator_module lastGreetedEvent
```

### 5.12 Stop the daemon

```bash
logoscore stop
```

```bash
sleep 2
```

### 5.13 Confirm the daemon has stopped

```bash
logoscore status
```

---

## Recap

| Composition path | In the orchestrator | Driven via `logoscore` |
| ---------------- | ------------------- | ---------------------- |
| Typed **sync** call | `greetThrough()` → `greeter.greet(...)` | `"Hello, World!"` |
| Composed sync calls | `greetReport()` → `greet` + `addInts` + `greetCount` | one map of three results |
| Typed **async** call | `startAsyncGreet()` → `greetAsync(..., cb)` | `queued`, then `"Hello, Async!"` |
| Typed **event** subscription | `subscribeGreeted()` → `onGreeted(cb)` | captured `"Hello, Events!"` |

Every module load and every one of these calls was brokered by the
`capability_module` built from the commit under test. A green run means this
capability-module change keeps module loading and inter-module composition —
exactly what the capability layer gates — working end to end, so the change
does not break downstream consumers.
