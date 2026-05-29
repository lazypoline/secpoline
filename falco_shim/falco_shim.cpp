
#include "falco_shim.h"
#include <stdio.h>
#include <stdlib.h> 
#include <string>

static std::string config_path;
static std::string rules_path;



ThreadSafeQueue plugin_queue;

void* shim_start(void* args){
    const char* falco_dir = getenv("FALCO_DIR");

    std::string base_dir = falco_dir ? falco_dir : "../falco";

    config_path = base_dir + "/falco.yaml";
    rules_path = base_dir + "/falco_rules.yaml";

    int argc = 5;

    char* argv[] = {"./falco/userspace/falco/falco", "-c", (char*)config_path.c_str(), "-r", (char*)rules_path.c_str(), 0};

    bool restart = false;
    std::string errstr;

    bool res = falco::app::run(argc, argv, restart, errstr);

    printf("res = %d, error %s\n", res, errstr.c_str());

    return nullptr;
}

int send_syscall(int syscall_num, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6){
    if(!plugin_queue.active) return 0;
    syscall_t* s = (syscall_t*)calloc(1, sizeof(syscall_t));
    s->syscall_num = syscall_num;
    s->arg1 = arg1;
    s->arg2 = arg2;
    s->arg3 = arg3;
    s->arg4 = arg4;
    s->arg5 = arg5;
    s->arg6 = arg6;
    return plugin_queue.push(s);
}
