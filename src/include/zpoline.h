#pragma once

#include "config.h"
#include "util.h"
#include <sys/mman.h>

void init_zpoline();

// implemented in asm_syscall_hook.asm
extern "C" void asm_syscall_hook(void);
extern "C" void syscall_hook_entry(void);

void rewrite_syscall_inst(uint16_t* syscall_addr, char compartment_id_on_entry);
