# Secpoline ProxySQL case study
This is the [ProxySQL](https://proxysql.com/) case study for Secpoline, where the proxy is integrated into Secpoline so it runs in-process.

## Building
Build Secpoline by following the steps in the [next section](#Secpoline:-A-Scalable-Approach-to-Build-Secure-In-Process-Syscall-Interposers). This build everything including the unmodified version of PorxySQL used for benchmarking.

> [!NOTE]
> On some machines, a rare issue may occur when building ProxySQL that causes the build to fail. This happens when a test case in one of ProxySQL’s dependencies fails during the build process.
>
> Rerunning `make` can resolve the issue, since the dependency is already built and will not be rebuilt on subsequent runs.

## Running

To start intercepting SQL requests, configure the ProxySQL configuration file, which will be available at [libproxysql/proxysql/etc/proxysql.cnf](libproxysql) once Secpoline has been built. In this file, you can set:

1. The port and address of the `mysql` server  
2. The port used by the proxy  
3. The credentials of the database user  
4. Any filters that should be applied to proxied queries  

Then attach Secpoline to an application that makes SQL requests:

```bash
PROXYSQL_CONFIG=path/to/libproxysql/proxysql/etc/proxysql.cnf path/to/output/libloader.so path/to/output/secpoline <some binary>
```

The script for the [sysbench benchmark](https://adriaanjacobs.github.io/files/sec26secpoline.pdf) can be found [here](libproxysql/benchmark/sysbench.sh).

To run the benchmark:

1. Install `mysql`.
2. Run the [initialization script](/libproxysql/benchmark/init_mysql_database.sh) to create the required database and user, or create them manually.  
   The database must be named `testdb`, and the user must have:
   - username: `appuser`  
   - password: `apppass`
3. Run the [sysbench script](libproxysql/benchmark/sysbench.sh).

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