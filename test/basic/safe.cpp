#include <cstdio>
#include <cstring>

unsigned int random()
{
    static unsigned int a = 2, b = 3, c = 5, x = 7;
    return x = a * x * x + b * x + c;
}

int main()
{
    unsigned int a[5];
    unsigned int *b = new unsigned int[5];

    a[4] = 12;
    a[random() & 3] ^= random();
    a[1] = 13;
    a[random() & 3] ^= random();
    a[2] = 14;
    a[random() & 3] ^= random();
    a[3] = 15;
    a[random() & 3] ^= random();

    b[4] = 16;
    b[random() & 3] ^= random();
    b[1] = 17;
    b[random() & 3] ^= random();
    b[2] = 18;
    b[random() & 3] ^= random();
    b[3] = 19;
    a[random() & 3] ^= random();

    printf("0x%x\n", a[4] ^ a[1] ^ a[2] ^ a[3]);
    printf("0x%x\n", b[4] ^ b[1] ^ b[2] ^ b[3]);

    int n = 0xfff;
    int *c = new int[n];

    memset(c, 0, sizeof(int) * n);
    for (int i = 0; i < n; ++i)
    {
        int v = random() & 0xffff;
        if (v < n)
            c[v] = random();
    }

    int x = 0;
    for (int i = 0; i < n; ++i)
        x ^= c[i];

    printf("0x%x\n", x);
}