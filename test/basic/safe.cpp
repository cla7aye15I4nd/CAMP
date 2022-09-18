#include <cstdio>

int main() {
    int a[4];

    a[0] = 1;
    a[1] = 2;
    a[2] = 3;
    a[3] = 4;

    printf("%d\n", a[0] + a[1] + a[2] + a[3]);

    int *b = new int[4];

    b[0] = 1;
    b[1] = 2;
    b[2] = 3;
    b[3] = 4;

    printf("%d\n", b[0] + b[1] + b[2] + b[3]);
}