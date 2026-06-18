#pragma once

#define DEBUG                       0
#define PRE_PRINT_SYSCALLS          0
#define POST_PRINT_SYSCALLS         0

#define SCAN_UNSAFE_INSTRUCTIONS    1
#define ISOLATE_FD                  1
#define TRACK_MAPPINGS              1
#define EXCLUSIVE_MPK_POLICY        1
#define PREVENT_MUTABLE_MAPS        1
#define MMAP_LOCK                   1
#define SAVE_VECTOR_REGS            1

#define PREVENT_NULL_DEREF          1
#define REWRITE_TO_ZPOLINE          1