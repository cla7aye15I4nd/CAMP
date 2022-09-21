#include "lib.h"

#define OVERFLOW_MAXSZ 0x7fff
#define OVERFLOW_OFFSET 48
#define IS_OVERFLOW(PTR) ((((uint64_t)PTR) >> OVERFLOW_OFFSET) != 0)
#define CLEAR_OVERFLOW(PTR) ((void*)(((uint64_t)(PTR)) & ((1LL << OVERFLOW_OFFSET) - 1)))
#define MARK_OVERFLOW(PTR, LEN) ((void *)(((uint64_t)PTR) | (((uint64_t)((uint16_t)(LEN))) << OVERFLOW_OFFSET)))
#define CHECK_OVERFLOW(LEN)                                        \
    do                                                             \
    {                                                              \
        if ((-OVERFLOW_MAXSZ > (LEN)) || ((LEN) > OVERFLOW_MAXSZ)) \
        {                                                          \
            perror("Overflow too many bytes");                     \
            abort();                                               \
        }                                                          \
    } while (0)

void *__violet_builtin_check(void *ptr, int64_t size, int64_t offset, int64_t needsize)
{
    int64_t overflow = 0;
    if (offset < 0)
        overflow = offset;
    else if (offset + needsize > size)
        overflow = offset + needsize - size;

    CHECK_OVERFLOW(overflow);
    return MARK_OVERFLOW(CLEAR_OVERFLOW(ptr), overflow);
}

void *__violet_gep_check(void *base, void *ptr, int64_t needsize)
{
    int64_t overflow = 0;

    CHECK_OVERFLOW(overflow);
    return MARK_OVERFLOW(ptr, overflow);
}


void *__violet_bitcast_check(void *ptr, int64_t needsize)
{
    int64_t overflow = 0;

    CHECK_OVERFLOW(overflow);
    return MARK_OVERFLOW(ptr, overflow);
}
