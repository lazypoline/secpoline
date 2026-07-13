# Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers
**Secpoline** is a secure in-process Linux syscall interposer and MPK sandbox that allows for arbitrary interposer functionality without compromising isolation. You can find more details in our USENIX'26 paper, ["Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers"](https://adriaanjacobs.github.io/files/sec26secpoline.pdf).

```bibtex
@inproceedings{sturm2026secpoline,
  title={Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers},
  author={Sturm, Ruben and  Schelfhout, Anton and G{\"u}lmez, Merve and Jacobs, Adriaan and Volckaert, Stijn},
  booktitle={Proceedings of the 35th USENIX Security Symposium (USENIX Security 2026)},
  year={2026},
  publisher={USENIX Association}
}
```

> [!NOTE]
> **Secpoline** is based on a _hybrid_ interposition mechanism from our previous paper, ["System Call Interposition Without Compromise"](https://adriaanjacobs.github.io/files/dsn24secpoline.pdf), located at [lazypoline/lazypoline](https://github.com/lazypoline/lazypoline). This repository supersedes that work, and adds security hardening as well as general bugfixes and usability improvements. 


## Building & Setup
During first time setup, install some dependencies:
```bash
apt install libaudit-dev musl-tools clang cmake libssl-dev
```


We use CMake for building. Typical usage as follows:
```bash
mkdir build
cd build
cmake ../
make -j
```

> [!IMPORTANT]
> If `REWRITE_TO_ZPOLINE` is set in [`src/include/config.h`](/src/include/config.h/) (default: yes), Secpoline will rewrite all encountered syscalls to use a [zpoline](https://github.com/yasukata/zpoline) trampoline for faster hooking on subsequent invocations.
> To enable this, Secpoline requires permissions to `mmap` at low virtual addresses, i.e., the 0 page.
> ```
> echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
> ```

> [!IMPORTANT]
> If `SCAN_UNSAFE_INSTRUCTIONS` is enabled in [`src/include/config.h`](/src/include/config.h/) (default: yes), `perf_event_open` needs access to place hardware breakpoints. These can be allowed via:
> ```bash
> echo 2 | sudo tee /proc/sys/kernel/perf_event_paranoid
> ```

## Running
Secpoline can hook syscalls in precompiled binaries by using the Secpoline loader using one of two methods:

Directly calling the Secpoline loader:
```bash
path/to/output/libloader.so path/to/output/secpoline <some binary>
```

Or updating the program headers to use the Secpoline loader as the default interpreter and setting the Secpoline environment variable:
```bash
patchelf --set-interpreter path/to/output/libloader.so <some binary>
SECPOLINE=path/to/secpoline <some binary>
```

> [!NOTE]
> Setting `SECPOLINE=DISABLE` allows application using the Secpoline loader as their default interpreter to run without Secpoline


This assumes that the libc program loader is located at `/lib64/ld-linux-x86-64.so.2`. If this is not the case use the environment variable `LOADER_PATH` to specify the actual location:
```bash
LOADER_PATH=path/to/ld.so path/to/output/libloader.so path/to/output/secpoline <some binary>
```


## Debugging and testing
We include a `main` binary that contains a number of testcases for Secpoline, e.g., multi-threading/multi-processing and signal delivery during trusted/untrusted execution.
```bash
# from the 'output' folder
gdb --args ./libloader.so ./secpoline ./main 
```

When debugging in gdb, gdb will pause on all signal delivery. This will be often as SUD uses SIGSYS and the MPK sanbox uses SIGSEGV and SIGTRAP. You can manually continue each time, or use `handle "signal" nostop` like:
```bash
# from the 'output' folder
gdb -ex "handle SIGSYS nostop noprint" -ex "handle SIGSEGV nostop noprint" -ex "handle SIGTRAP nostop noprint pass" --args ./libloader.so ./secpoline ./main
```

> [!NOTE]
> `handle SIGTRAP pass` can cause the program to terminate if a breakpoint is triggered before the SIGTRAP handler is installed, or during short windows where the signal is temporarily blocked.

> To avoid this issue, you can use `handle SIGTRAP nopass` if you do not intend to test hardware breakpoint functionality while debugging.

Debug symbols for the application and Secpoline itself do not load in properly, so we provide a gdb script in the [debug_scripts](/debug_scripts/) directory to load them in at run time as follows:
```bash
# in gdb
source ./debug_scripts/process_symbols.py
asa
```

## Security Evaluation
Building Secpoline also builds a set of Proof-of-Concept attacks agains MPK sandboxes. These can be found in [output/security_eval](output/security_eval). These tests are build with the Secpoline loader as their default interpreter.

### Forged signal delivery
The [foged signal delivery](/tests/forged_signal.cpp) attack tries to manually jump to the signal handler entry point. It attempts to confuse the monitor by entering here on a untrusted stack instead of the trusted `sigaltstack`. Then, once the monitor is running on an untrusted stack, the attack overwrites a return address on that stack to redirect control flow to a malicous function while the MPK permissions are still high.

This attack requires some manual setup work as it needs to know offsets within the program that depend on which depends on version, compiler flags, compiler version,... to trigger undefined behavior:

1) Determine the location of the signal entry point. Using a debugger, manually find the relative offset from the base address of `libsegfault_handler.so` to `asm_signal_entry()` and update `ENTRY_OFFSET` with this relative offset.
2) Now you need to find the address of a return address to overwrite. Using a debugger, stop at the line `"mov %%rsp, %%r11\n\t"` and find the relative offset to a return address on the stack that returns to trusted code such as the one that returns to `invoke_app_specific_handler`. Update `STACK_OFFSET` with this offset.

## Configuring and Extending
You can modify Secpoline to better fit your needs. To add a new syscall handler follow these three steps:
1) Write a new handler function by following the examples in [src/syscall_handlers/main_monitor.cpp](src/syscall_handlers/main_monitor.cpp)
2) Declare the new function in [src/include/secpoline.h](src/include/secpoline.h)
3) Link the new handler to its syscall in [src/secpoline.cpp](src/secpoline.cpp) [initialise_syscall_handlers()]

[src/include/config.h](src/include/config.h) contains some options to control Secpoline's behavior. Most are self-explanatory.

## Compatibility
Secpoline is well-tested on Ubuntu 20.04, 22.04, and 24.04. Its primary compatibility requirement is kernel version >= 6.12 for a [necessary bugfix](https://lore.kernel.org/all/20240802061318.2140081-2-aruna.ramakrishna@oracle.com/) in the Linux kernel in secure mode.