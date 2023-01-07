#include <stdio.h>
#include <stdlib.h>

#define LEN 1000000000

char randc() {
    static unsigned int c = 100;
    return (char)((c = c * c) % 26 + 'a');
}

void gstr(char *s) {
    for (int i = 0; i < LEN; ++i)
        *s++ = randc();
}

int diff(char *s, char *t) {
    int count = 0;
    for (int i = 0; i < LEN; ++i)
        count += *s++ != *t++;
    return count;
}

int main() {
    char* s = malloc(LEN);
    char* t = malloc(LEN);
    gstr(s);
    gstr(t);
    printf("%d\n", diff(s, t));
}