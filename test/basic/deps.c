#include <stdio.h>
#include <stdlib.h>

struct node {
    int *xs;
    int len;
};

void __attribute__((noinline)) create(struct node *nd, int extra)
{
    nd->xs[nd->len - 1] = 1;
    nd->xs[nd->len - 2] = 2;
    nd->xs[nd->len - 3] = 3;


    nd->xs[extra - 1] = 1;
    nd->xs[extra - 2] = 2;
    nd->xs[extra - 3] = 3;
}

int main() {
    struct node *nd = malloc(sizeof(struct node));
    nd->len = 3;
    nd->xs = malloc(nd->len * sizeof(int));
    create(nd, 3);
    printf("%d %d %d\n", nd->xs[0], nd->xs[1], nd->xs[2]);
}