#include <cstdio>

int Eratosthenes(int n)
{
    int *is_prime = new int[n];
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

int Euler(int n)
{
    int *is_prime = new int[n];
    int *prime = new int[n];
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
    printf("The maximum prime between 1 ~ 100000 is %d\n", Eratosthenes(100000));
    printf("The maximum prime between 1 ~ 1000000 is %d\n", Eratosthenes(1000000));
    printf("The maximum prime between 1 ~ 10000000 is %d\n", Eratosthenes(10000000));
    printf("The maximum prime between 1 ~ 100000000 is %d\n", Eratosthenes(100000000));

    printf("The number of prime between 1 ~ 100000 is %d\n", Euler(100000));
    printf("The number of prime between 1 ~ 1000000 is %d\n", Euler(1000000));
    printf("The number of prime between 1 ~ 10000000 is %d\n", Euler(10000000));
    printf("The number of prime between 1 ~ 100000000 is %d\n", Euler(100000000));

    return 0;
}