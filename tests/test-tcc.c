#include <stdio.h>
#include <unistd.h>

#define my_syscall0(num)                                                      \
({                                                                            \
	long _ret;                                                            \
	register long _num  __asm__ ("rax") = (num);                          \
									      \
	__asm__ volatile (                                                    \
		"syscall\n"                                                   \
		: "=a"(_ret)                                                  \
		: "0"(_num)                                                   \
		: "rcx", "r11", "memory", "cc"                                \
	);                                                                    \
	_ret;                                                                 \
})

int main() {
    pid_t pid = my_syscall0(39);
    printf("hello my pid is %d\n", pid); 
    return 0;
}
