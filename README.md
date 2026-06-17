# Secpoline Falco case study
[Falco engine](https://falco.org/) integrated into the Secpoline monitor.

## Configuring Falco
In the Falco directory, update [falco.yaml](/falco/falco.yaml) and [falco_base.yaml](/falco/falco_base.yaml) by changing the following line to the absolute path of the [Secpoline plugin](falco_shim/secpoline_plugin/).
```bash
library_path: /PATH/TO/falco_shim/secpoline_plugin/libsecpoline_plugin.so
```
Now you can build Secpoline with the integrated Falco engine by following the steps in the [next section](#Secpoline:-A-Scalable-Approach-to-Build-Secure-In-Process-Syscall-Interposers).

## Adding new rules
To add new rules to the Falco engine, update the [rules file](/falco/falco_rules.yaml). You can define rules using the `secpoline` identifier to use syscalls intercepted by Secpoline.

Available fields:

- **secpoline.syscall_num**: syscall number
- **secpoline.arg1**-**secpoline.arg6**: syscall arguments

> [!WARNING]
> In the current prototype, only direct syscall arguments are available for matching.
> Dereferencing pointers or inspecting structs referenced by syscall arguments is not supported.

Example:

```yaml
- rule: Detect reads from stdin
  desc: Detect processes reading from stdin using the read syscall
  condition: secpoline.syscall_num = 0 and secpoline.arg1 = 0
  output: "Process performed a read from stdin"
  priority: WARNING
  source: secpoline
```

## Running
To start detecting intrusions, run any binary using the Secpoline loader. Furthermore, the FALCO_DIR env variable should point to the [Falco directory](/falco).
```bash
FALCO_DIR=/path/to/falco/dir/ path/to/output/libloader.so path/to/output/secpoline <some binary>
```

You can also run the [Zip benchmark](/benchmarks/falco_benchmarks/zip_bench.sh) from [our paper](https://adriaanjacobs.github.io/files/sec26secpoline.pdf). This will pull in the Linux kernel source and zip it up while being monitored by either nothing, Falco with its kernel module, or Falco using Secpoline. This script requires Secpoline to be built.

> [!WARNING]
> This benchmark will install a kernel module that intercepts syscalls system-wide. The module is automatically uninstalled at the end of the script.

# Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers
**Secpoline** is a secure in-process Linux syscall interposer and MPK sandbox that allows for arbitrary interposer functionality without compromising isolation. You can find more details in our USENIX'26 paper, ["Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers"](https://adriaanjacobs.github.io/files/sec26secpoline.pdf).

```bibtex
@inproceedings{sturm2026secpoline,
  title={Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers},
  author={Sturm, Ruben and  Schelfhout, Anton and G{\"u}lmez, Merve and Jacobs, Adriaan and and Volckaert, Stijn},
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

## Configuring and Extending
You can modify Secpoline to better fit your needs. To add a new syscall handler follow these three steps:
1) Write a new handler function by following the examples in [src/syscall_handlers/main_monitor.cpp](src/syscall_handlers/main_monitor.cpp)
2) Declare the new function in [src/include/secpoline.h](src/include/secpoline.h)
3) Link the new handler to its syscall in [src/secpoline.cpp](src/secpoline.cpp) [initialise_syscall_handlers()]

[src/include/config.h](src/include/config.h) contains some options to control Secpoline's behavior. Most are self-explanatory.

## Compatibility
Secpoline is well-tested on Ubuntu 20.04, 22.04, and 24.04. Its primary compatibility requirement is kernel version >= 6.12 for a [necessary bugfix](https://lore.kernel.org/all/20240802061318.2140081-2-aruna.ramakrishna@oracle.com/) in the Linux kernel in secure mode.