
## Bugfixes
- [x] Use proper locking in signal disposition management
- [x] Deal with thread exit (unmap gsregion)
    * incl. unmapping the current stack properly
- [x] SUD syscall handling outside of syscall context to deal with signal delivery during syscall emulation
- [x] Use sigaltstack to run the SIGSYS handler
    * We push to the app stack, could technically overwrite (part of) the signal handler frame
    * thread creation clears altstacks in child, we should reinstall them
- [x] Support execve
    * Wasn't very hard for now: LD_PRELOAD remains set for any execve'd programs -> secpoline gets properly re-initialized
- [ ] Do not allow signal handlers to mask off SIGSYS
- [ ] Do not unconditionally restore code pages to PROT_READ|PROT_EXEC after zpoline rewrite: dynamically generated code may have had the page writable already
    * watch out for race conditions on page permissions changes while checking this
    * turns out benign programs wont W+X any pages (even JIT). we can provide a compatibility mode for those who do: grant access on segfaults for pages requested as W+X
    * tcc does it. we probably have to support by parsing /proc/maps
- [ ] There's technically a memory leak where signal dispositions never get unmapped
    * This is probably easily fixable by reference counting. Never got around to it
- [ ] Testen met coreutils, linux test project (LTP), [glibc-benchtests](https://github.com/xCuri0/glibc-benchtests)

## Features
- [ ] I would like to expose the full register context to the app similar to how existing expressive interposers can do it (mcontext)
- [ ] Is it possible to replace the indirect jump at the end of the NOP sled with a direct jmp/call?
- [ ] Support application use of MPK, too (securely)
    * Ideally without providing wrappers to interposer functions. But realistically, provide wrappers
- [ ] Support CET. The zpoline indirect branch terminates in NOP, not ENDBR. ENDBR is larger than 1 byte though, so we cannot place it at every valid syscall landing location in the zero page.
    * For SHSTK, we have to add SHSTK-adjusting code to `restore_selector_trampoline`. A previous version of this code contains a SHSTK-compatible version.
    * For IBT, we have to mark the zero page as a legacy code page in the legacy code bitmap.
- [ ] Make the syscall arguments modifiable for emulated-later system calls
- [ ] If the app sigreturns itself (from inside the signal handler), our trampoline won't be called
- [x] Always set SA_SIGINFO for application signal handlers: we access the siginfo stuff every time
- [x] Prevent race condition where a rewriter revokes read permissions while another thread is rewriting
- [x] Include the zpoline optimized NOP sled
    * we modified it to our own custom design, which avoids the pushes and the associated multiplication and pop
    * we also use multi-byte nops in the tail/blast zone of the sled
- [x] Support vfork
- [ ] Adhere more thoroughly to the ABI: set rcx, r11, and rflags correctly
    * especially RCX: it should contain the address after the syscall inst (`rip_after_syscall`). Some apps _will_ depend on it
- [ ] Use application altstack as untrusted stack when requested
- [ ] Support running setuid binaries, like sudo
    * Do we need a seperate copy of the loader for this? setuid-enabled? A setuid loader is probably a terrible idea
    * How does sudo normally get loaded?
- [ ] Support setting the secpoline loader as the program interpreter, so programs can be loaded directly as `./program`
    * This helps with embedding secpoline into custom-generated binaries in benchmark suites, such as coreutils or the SPEC suites


## Assumption validations
- [ ] stack access beyond RSP across syscalls
    * this is already a reported issue with zpoline, notably with the red-zone feature of the x86-64 ABI, where compilers can use a 128-byte region below rsp at will
        * https://github.com/yasukata/zpoline/issues/9
- [x] register preservation across syscalls
    * normally, a syscall preserves _all_ registers except rax (retval), r11 (flags), and rcx (return address from kernel POV). 
    * syscall handlers can call arbitrary code, that clobbers arbitrary registers
    * saving & restoring all registers (incl FP state) up front might be too expensive
    * zpoline preserves callee-saved regs from C calling conv. Reasoning is (presumably) that most syscalls are called from functions that have this calling conv (e.g. libc). _This is not correct_. 
        * Manually-written code that uses assembly files to call syscalls will have its own assumptions about what registers are preserved
        * Compilers will generate code that assumes register preservation based on inline asm clobber lists:
            * Glibc uses inline asm to call most syscalls, and uses a realistic (small) clobber list: https://elixir.bootlin.com/glibc/latest/source/sysdeps/unix/sysv/linux/x86_64/sysdep.h#L221
            * Non-libc code also sometimes uses inline asm syscalls directly, e.g., https://lore.kernel.org/lkml/YWg%2FJk4RX7gvkXAG@zn.tnic/t/
    * it indeed happens in real code (ask Alicia). We have a fix for it in the config now
- [x] Try to find dynamically-generated syscall instructions and show that zpoline doesn't intercept them while we do
    * tcc does it
- [ ] Find applications that do the NULL access emulation. 
    * It sounds like a gimmick tbh. Alex once suggested using hardware breakpoints on NULL to get the same behavior, but I'm not convinced anyone actually cares
- [ ] Benchmark our optimized NOP sled against zpoline's.
- [ ] If we disable SMAP, does it fix our SUD passthrough performance penalty?

## Security issues
The Endokernel people seem to have worked on secure SUD usage: https://arxiv.org/pdf/2406.07429
- [ ] Avoid malicious code overwrites during zpoline syscall rewrite in multi-threaded programs
- [x] Protect the gsrel region & signal handler dispositions
    * we need more than 1 MPK domain to provide confidentiality to the trusted interceptor
- [x] Use safe stack to pass privilege level to sigreturn trampoline
- [ ] Attackers can abuse the wrgsbase instruction
- [x] Protect the in-process monitor stack (switch stacks)
    * This will affect many of the clone, fork, vfork handling
- [x] Protect the rip_after_syscall that gets pushed to the app stack by `call *%rax`
    * we don't need to, it's app data
- [ ] Protect the SIGSYS stack & saved regs
- [ ] Protect the stack & saved regs of regular signals' handlers when they are delivered during privileged execution
    * always deliver to MPK-secured altstack. how to run untrusted handlers?
        * switch stacks to an untrusted stack
        * how to stop ucontext changes?
            * provide read-only ucontext access to apps? 
                * application shouldnt be able to read secpoline regs
            * ignore changes made to ucontext when in privileged?
            * pass the application's ucontext instead of secpoline's ucontext?
        * provide read-only ucontext access to apps? or ignore changes made to ucontext when in privileged?
- [x] Protect the initial stack of any cloned threads
- [ ] Attackers can abuse wrgsbase to attack monitor
- [ ] Prevent attacker from mmap'ing over safe regions (like NOP sled)
- [ ] What about side-channel leakage out of the syscall interposer?
- [ ] TOCTOU attacks can make it hard for the interposer to reliably check the arguments
    * fix: https://download.vusec.net/papers/safefetch_sec24.pdf

## Use cases
- [ ] Prevent access to sensitive /proc files (PKU use case)
- [x] Printing out syscalls strace-style
