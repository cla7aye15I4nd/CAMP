#include <cstdio>
#include <cstring>

unsigned int random()
{
    static unsigned int a = 2, b = 3, c = 5, x = 7;
    return x = a * x * x + b * x + c;
}

int main()
{
    int a[1000];
    for (int i = 0; i < 1000; ++i)
    {
        int v = random() % 1001;
        if (v >= 1000)
            printf("ERROR(%d)\n", v);
        a[v] = random();
    }

    int x = 0;
    for (int i = 0; i < 1000; ++i)
        x ^= a[i];

    printf("0x%x\n", x);
}