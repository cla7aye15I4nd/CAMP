#include <stdio.h>
#include <stdlib.h>

int __attribute__ ((noinline)) Eratosthenes(int *is_prime, int n)
{
    int max_prime = 0;

    for (int i = 0; i < n; ++i)
        is_prime[i] = 1;

    is_prime[0] = is_prime[1] = 0;
    for (int i = 2; i < n; ++i)
    {
        if (is_prime[i])
        {
            max_prime = i;
            if ((long long)i * i < n)
                for (int j = i * i; j < n; j += i)
                    is_prime[j] = 0;
        }
    }

    return max_prime;
}

int __attribute__ ((noinline)) Euler(int *is_prime, int n)
{
    int *prime = (int*) malloc(sizeof(int) * n);
    int cnt = 0;

    for (int i = 0; i < n; ++i)
        is_prime[i] = 1;

    is_prime[0] = is_prime[1] = 0;

    for (int i = 2; i < n; ++i)
    {

        if (is_prime[i])
            prime[cnt++] = i;

        for (int j = 0; j < cnt; ++j)
        {
            if ((long long)i * prime[j] >= n)
                break;
            is_prime[i * prime[j]] = 0;
            if (i % prime[j] == 0)
            {
                break;
            }
        }
    }

    return cnt;
}

int main()
{
    int *is_prime = (int*) malloc(sizeof(int) * 100000);

    int res = 0;
    for (int n = 0; n < 100000; n += 10)
        res ^= Eratosthenes(is_prime, n) ^ Euler(is_prime, n);

    printf("FLAG: %d\n", res);

    return 0;
}