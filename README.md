# secpoline falco case study
[Falco engine](https://falco.org/) integrated into the secpoline monitor.

## Configuring Falco
Specify the paths to the falco config and rules files in ./falco_shim/falco_shim.cpp.

Specify the path the the secpoline plugin in the falco config file ./falco/falco.yaml. 
this has to be an absolute path, the plugin is located in the falco_shim directory.


# Secpoline
**secpoline** is a secure in-process syscall interposer and MPK sandbox that allows for arbitrary interposer functionality without compromising isolation. It uses a _hybrid interposition_ mechanism based on ["System Call Interposition Without Compromise"](https://adriaanjacobs.github.io/files/dsn24secpoline.pdf).

```bibtex
@inproceedings{sturm2026secpoline,
  title={Secpoline: A Scalable Approach to Build Secure In-Process Syscall Interposers},
  author={Sturm, Ruben and  Schelfhout, Anton and G{\"u}lmez, Merve and Jacobs, Adriaan and and Volckaert, Stijn},
  booktitle={Proceedings of the 35th USENIX Security Symposium (USENIX Security 2026)},
  year={2026},
  publisher={USENIX Association}
}
```

## Building
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

Just like [zpoline](https://github.com/yasukata/zpoline), secpoline requires permissions to `mmap` at low virtual addresses, i.e., the 0 page.
When enabling the MPK sanbox, `perf_event_open` needs access to place hardware breakpoints. These can be allowed via:
```bash
echo 0 | sudo tee /proc/sys/vm/mmap_min_addr
echo 2 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

## Running
secpoline can hook syscalls in precompiled binaries by using the secpoline loader using one of two methods,

Directly calling the secpoline loader:
```bash
path/to/build/libloader.so path/to/build/secpoline <some binary>
```

Or updating the program headers to use the secpoline loader as the default interpreter and setting the secpoline environment variable:
```bash
sudo patchelf --set-interpreter path/to/output/libloader.so <some binary>
SECPOLINE=path/to/secpoline <some binary>
```

This assumes that the libc program loader is located at `/lib64/ld-linux-x86-64.so.2`. If this is not the case use the environment variable `LOADER_PATH` to specify the actual location:
```bash
LOADER_PATH=path/to/ld.so path/to/build/libloader.so path/to/output/secpoline <some binary>
```


## Debugging and testing
We include a `main` binary that contains a number of testcases for secpoline, e.g., multi-threading/multi-processing and signal delivery during trusted/untrusted execution.
```bash
# from the 'output' folder
gdb --args ./libloader.so ./secpoline ./main 
```

When debugging in gdb, gdb will pause on all signal delivery. This will be often as SUD uses SIGSYS and the MPK sanbox uses SIGSEGV and SIGTRAP. You can manually continue each time, or use `handle "signal" nostop` like:
```bash
# from the 'build' folder
gdb -ex "handle SIGSYS nostop noprint" -ex "handle SIGSEGV nostop noprint" -ex "handle SIGTRAP nostop noprint pass" --args ../output/libloader.so ../output/secpoline ../output/main
```

Debug symbols for the application and secpoline itself do not load in properly, so we provide a gdb script in the `debug/` directory to load them in at run time as follows:
```bash
# in gdb
source ./debug/process_symbols.py
asa
```

## Configuring and Extending
You can modify secpoline to better fit your needs. To add a new syscall handler follow these three steps:
1) Write a new handler function by following the examples in [src/syscall_handlers/main_monitor.cpp](src/syscall_handlers/main_monitor.cpp)
2) Declare the new function in [src/include/secpoline.h](src/include/secpoline.h)
3) Link the new handler to its syscall in [src/secpoline.cpp](src/secpoline.cpp) [initialise_syscall_handlers()]

[src/include/config.h](src/include/config.h) contains some options to control secpoline's behavior. Most are self-explanatory.

## Compatibility
secpoline is well-tested on Ubuntu 20.04, 22.04, and 24.04. Its primary compatibility requirement is kernel version >= 6.12 for a [necessary bugfix](https://lore.kernel.org/all/20240802061318.2140081-2-aruna.ramakrishna@oracle.com/) in the Linux kernel in secure mode. 
