#include <pthread.h>

int virual_clone_wrapper(size_t flags, size_t* child_stack, [[maybe_unused]] size_t ptid, size_t ctid, size_t tls);