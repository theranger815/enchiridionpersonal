# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Enchiridion is a C-based agent (payload) for the [Mythic C2 framework](https://github.com/its-a-feature/Mythic). It targets Linux hosts, communicates with a Mythic server via configurable C2 profiles (currently HTTP/HTTPS, with WebSocket support planned), and executes tasks.

This project is built specifically for use in a training environment for teaching blue team and red team cybersecurity skills to prospective naval officers. It is intended to be deployed and operated only within isolated training ranges and lab environments to give trainees hands-on experience with C2 agent behavior, detection, and defense.

The project has two layers:

- **Python layer** (`agent_functions/`): Mythic framework integration — defines commands for the UI, handles configuration, and orchestrates the CMake build.
- **C layer** (`agent_code/`): The actual runtime agent binary — check-in, tasking loop, command execution.

## Repository Layout

```
Payload_Type/enchiridion/
├── main.py                          # Starts the mythic_container service
└── enchiridion/
    ├── __init__.py                  # Dynamically imports all agent_functions
    ├── agent_code/                  # C source + CMake build system
    │   ├── CMakeLists.txt
    │   ├── cmake/                   # Toolchain + ExternalProject deps
    │   ├── include/                 # Headers (config.h has %PLACEHOLDER% tokens)
    │   └── src/
    │       ├── enchiridion.c        # main(), checkIn(), taskingLoop()
    │       ├── agent.c              # Agent struct init
    │       ├── c2/http.c            # libcurl-based C2 comms
    │       └── commands/            # shell.c, ls.c, download.c
    └── agent_functions/
        ├── builder.py               # PayloadType class, config templating, CMake invocation
        ├── shell.py / ls.py / download.py / exit.py
```

## Build System

The agent is compiled with CMake using a musl cross-compilation toolchain for fully static, stripped binaries. Dependencies (zlib, WolfSSL, libcurl) are fetched and built automatically via CMake `ExternalProject`.

**Manual build (from `agent_code/`):**
```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/musl-toolchain.cmake
cmake --build build -j$(nproc)
```

**Normal flow:** The build is driven by Mythic via `builder.py`'s `EnchiridionAgent.build()` method, which substitutes `%PLACEHOLDER%` tokens in `include/config.h` before invoking CMake.

**Build parameters (from Mythic UI):**
- `Build Type`: Release (default) or Debug
- `NUMTHREADS`: Worker thread count (default 1)

## Python Environment

The Python container uses Python 3.13 with a `.venv/` virtual environment. Entry point is `main.py`, which calls `mythic_container.mythic_service_container()`. The `enchiridion/__init__.py` dynamically imports all modules from `agent_functions/` so adding a new command file is sufficient.

## C Agent Architecture

**Startup flow:** `main()` → `initAgent()` → `checkIn()` → `taskingLoop()` + threadpool.

**Task lifecycle:**
1. `taskingLoop()` GETs tasks from C2 via `getTasking()` (HTTP POST with base64 JSON)
2. Tasks enqueued to thread pool; each worker decodes the JSON task, dispatches to the matching command function
3. Command returns a `TaskResponse` struct; `sendTaskResponse()` POSTs result back to C2

**C2 communication:** All messages are base64-encoded JSON. The C2 transport is profile-driven; the current implementation uses HTTP via libcurl with SSL verification disabled, optional proxy support, and configurable user-agent and sleep interval. WebSocket is a planned profile.

**config.h** is a template — never edit the placeholder tokens directly. `builder.py` does string substitution (`%UUID%`, `%HOSTNAME%`, `%PORT%`, `%ENDPOINT%`, `%PROXYURL%`, `%USERAGENT%`, `%STATIC_KEY%`, etc.) before building.

## Adding a New Command

1. Add `commands/yourcommand.c` implementing `TaskResponse* yourcommand(Task* task, Agent* agent)` and declare it in `include/commands.h`.
2. Add the source to `CMakeLists.txt`.
3. Add `agent_functions/yourcommand.py` with a Mythic command class (subclass `CommandBase`).
4. The `__init__.py` dynamic loader will pick it up automatically.

## No Test Suite

There is no automated test infrastructure. Validation is done by running the agent against a live Mythic instance.
