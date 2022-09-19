#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef DEBUG
#define DEBUG_LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    void *__violet_gep_check(void *, void *, int64_t);
    void *__violet_bitcast_check(void *, int64_t);
    void *__violet_builtin_check(void *, uint8_t, int64_t, int64_t);

#ifdef __cplusplus
}
#endif