# ts — tiny & sweet

A collection of single-header C++23 utilities for game and engine development.
Almost no dependencies between headers (only ts_net depends on ts_scheduler for the Fence class). Drop in what you need, ignore the rest.

| Header | Description |
|---|---|
| `ts_ecs.h` | Entity-Component-System scene with sparse sets and a fluent query API |
| `ts_scheduler.h` | Multi-threaded task scheduler with Vulkan-flavored semaphore/fence synchronization |
| `ts_vfs.h` | Virtual filesystem with explicit mount points and pluggable providers |
| `ts_vfs_zip.h` | Zip archive provider for `ts_vfs` (requires [miniz](https://github.com/richgel999/miniz)) |

## Requirements

- C++23
- `ts_vfs_zip.h` requires miniminiz (single-header, public domain, included in this repo)

## Usage

Each header is self-contained. Define the corresponding `_IMPLEMENTATION` macro in exactly one translation unit:

```cpp
#define TS_SCHEDULER_IMPLEMENTATION
#include <ts/ts_scheduler.h>

#define TS_VFS_IMPLEMENTATION
#include <ts/ts_vfs.h>

#define TS_VFS_ZIP_IMPLEMENTATION
#include <ts/ts_vfs_zip.h>

// ts_ecs.h is header-only, no macro needed.
#include <ts/ts_ecs.h>
```

## A fair warning

ts_net, as is, might be a bit wonky. Threads are detached on creation so you have to ensure all connections are closed before exiting.
Also, Winsock being Winsock, you have to include ts_net.h before anything that might include windows files.

## Note on AI use

All documentation, including parts of this file, has been written by Claude, with slight adjustments by myself.
While I did generate a small portion of the code through AI, none has been pasted as is, and everything's been proofread (but I'm not foolproof myself).

## License

[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)
