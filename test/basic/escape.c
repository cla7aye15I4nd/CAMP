#include <stdio.h>
#include <stdlib.h>

#define SIZE 0x1000
char **pool;

unsigned int randnum()
{
    static unsigned int a = 2, b = 3, c = 5, x = 7;
    return x = x * x * a + b * x + c;
}

int main()
{
    pool = (char **)malloc(sizeof(char *) * SIZE);
    for (int i = 0; i < SIZE; ++i)
    {
        pool[i] = (char *)malloc(sizeof(char));
        pool[i][0] = (i % 26) + 'a';
    }

    for (int k = 0; k < SIZE; ++k)
    {
        for (int i = 1; i < SIZE; ++i)
        {
            int j = randnum() % i;
            char *tmp = pool[i];
            pool[i] = pool[j];
            pool[j] = tmp;
        }
    }

    for (int i = 0; i < SIZE; ++i) {
        putchar(*pool[i]);
        free(pool[i]);
    }
    putchar(10);
    free(pool);

    return 0;
}