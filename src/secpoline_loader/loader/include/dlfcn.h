#pragma once

void * dlopen(const char * name, int flags);
int dlclose(void * handle);

void * dlsym(void * handle, const char * symbol);
