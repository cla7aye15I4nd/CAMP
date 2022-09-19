#include "lib.h"

void *__violet_gep_check(void *base, void *result, int64_t size)
{
    DEBUG_LOG("[__gep_check] %p %p %ld\n", base, result, size);
    return result;
}

void *__violet_bitcast_check(void *ptr, int64_t size) {
    DEBUG_LOG("[__bitcast_check] %p\n", ptr);
    return ptr;
}

void *__violet_builtin_check(void *ptr, uint8_t cond, int64_t size, int64_t offset) {
    return ptr;
}