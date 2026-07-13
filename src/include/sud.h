#pragma once

#include "config.h"
#include <sys/prctl.h>
#include "gsreldata.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
# define PR_SET_SYSCALL_USER_DISPATCH	59
# define PR_SYS_DISPATCH_OFF	0
# define PR_SYS_DISPATCH_ON	1
# define SYSCALL_DISPATCH_FILTER_ALLOW	0
# define SYSCALL_DISPATCH_FILTER_BLOCK	1
#endif

# define SYS_USER_DISPATCH_INTERNAL 2	/* syscall user dispatch triggered */

inline void set_sud_allow(){
    gsreldata->readable_data.sud_selector = SYSCALL_DISPATCH_FILTER_ALLOW;
}

inline void set_sud_block(){
    gsreldata->readable_data.sud_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

inline char get_sud(){
    return gsreldata->readable_data.sud_selector;
}

void init_sud();