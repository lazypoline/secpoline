#include <stdio.h>

extern "C" unsigned long bench_syscall(unsigned long syscall_no);

int main() {
    auto cycles = bench_syscall(500);

    fprintf(stderr, "Cycles: %lu\n", cycles);
}
