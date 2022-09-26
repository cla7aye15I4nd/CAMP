#include <stdio.h>
#include <stdlib.h>

int __attribute__ ((noinline)) fib(int *a, int n) {
    a[0] = 1;
    a[1] = 1;
    for (int i = 2; i <= n; ++i)
        a[i] = a[i - 1] + a[i - 2];
    
    return a[n];
}

int __attribute__ ((noinline)) square_sum(int *a, int n) {
    int sum = 0;
    for (int i = 0; i < n; ++i)
        a[i] = i * i;
    for (int i = 0; i < n; ++i)
        sum += a[i];
    
    return sum;
}

int main() {
    int *a = (int *) malloc(sizeof(int) * 1000);

    printf("fib[10] = %d\n", fib(a, 20));
    printf("sum(i^2, 10) = %d\n", square_sum(a, 100));

    return 0;
}