#pragma once

#include "../../types.h"
#include <stdlib.h>

extern size_t rsp_holder;


extern void load_secpoline(int argc, char ** argv, char ** envp, struct mmapped_list_s* loader_mappings, size_t* rip_after_setup);
extern void asm_load_secpoline(int argc, char ** argv, char ** envp, struct mmapped_list_s* loader_mappings);
struct mmapped_list_s* get_mappings();