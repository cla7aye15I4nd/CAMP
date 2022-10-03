#include <stdio.h>
#include <stdlib.h>

struct state_t
{
    __int64_t count1;
    __int64_t count2;
    __int64_t count3;
};

void search(struct state_t *state, int depth)
{
    __int64_t tmp = ++state->count1;
    state->count1 += state->count2;
    state->count2 += state->count3;
    state->count3 += tmp;

    if (depth == 12)
        return;
    for (int i = 0; i <= depth; ++i)
        search(state, depth + 1);
}

int main()
{
    struct state_t *a = (struct state_t *) malloc(sizeof(struct state_t));
    struct state_t *b = (struct state_t *) malloc(sizeof(struct state_t));
    struct state_t *c = (struct state_t *) malloc(sizeof(struct state_t));
    
    a->count1 = 0;
    a->count2 = 0;
    a->count3 = 0;

    b->count1 = 0;
    b->count2 = 0;
    b->count3 = 0;

    c->count1 = 0;
    c->count2 = 0;
    c->count3 = 0;
    
    search(a, 0);
    search(b, 0);
    search(c, 0);

    printf("1: %ld\n", a->count1);
    printf("2: %ld\n", b->count2);
    printf("3: %ld\n", c->count3);
}