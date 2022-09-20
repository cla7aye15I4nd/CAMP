#include "lib.h"

#define OVERFLOW_MAXSZ 0x7fff
#define OVERFLOW_OFFSET 48
#define MARK_OVERFLOW(PTR, LEN) ((void *)(((uint64_t)PTR) | (((uint16_t)(LEN)) << OVERFLOW_OFFSET)))
#define CHECK_OVERFLOW(LEN)                                    \
    do                                                         \
    {                                                          \
        if (-OVERFLOW_MAXSZ > (LEN) || (LEN) < OVERFLOW_MAXSZ) \
        {                                                      \
            perror("Overflow too many bytes");                 \
            abort();                                           \
        }                                                      \
    } while (0)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshift-count-overflow"
void *__violet_builtin_check(void *ptr, int64_t size, int64_t offset)
{
    int64_t overflow = 0;
    if (offset < 0)
        overflow = offset;
    else if (offset > size)
        overflow = offset - size;

    CHECK_OVERFLOW(overflow);
    return MARK_OVERFLOW(ptr, overflow);
}

void *__violet_gep_check(void *base, void *result, int64_t size)
{
    int64_t overflow = 0;

    CHECK_OVERFLOW(overflow);
    return MARK_OVERFLOW(result, overflow);
}
#pragma GCC diagnostic pop

void *__violet_bitcast_check(void *ptr, int64_t size)
{
    return ptr;
}
