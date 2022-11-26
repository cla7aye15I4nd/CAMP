#include <stdio.h>
#include <stdlib.h>

int main()
{
    int **a = (int **)malloc(sizeof(int *) * 8);
    for (int i = 0; i < 8; ++i)
    {
        a[i] = (int *)malloc(sizeof(int));
        a[i][0] = i;
    }

    int x = 2;
    for (int i = 0; i < 8; ++i)
        if ((x *= 2) > 32) {
            printf("free %d\n", i);
            free(a[i]);
            break;
        }

    for (int i = 0; i < 8; ++i)
        printf("%d\r", a[i][0]);
}