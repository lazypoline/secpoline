#pragma once

#include <stdint.h>

/* 
    on x86-64 (which is the only arch we target) 
    this is always correct
*/
typedef struct {
    uint64_t sig;
} kernel_sigset_t;
#ifndef __x86_64__
    #error Unsupported arch, update kernel_sigset_t!
#endif

struct kernel_sigaction
{
  void (*k_sa_handler) (int);
  unsigned long sa_flags;
  void (*sa_restorer) (void);
  kernel_sigset_t sa_mask;
};
