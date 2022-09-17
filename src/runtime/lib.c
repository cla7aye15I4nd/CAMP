#include "lib.h"

void *__gep_check(void *base, void *result, int64_t size)
{
    DEBUG_LOG("[__gep_check] %p %p %ld\n", base, result, size);
    return result;
}
