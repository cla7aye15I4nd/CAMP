#include <string.h>
#include <stdio.h>

unsigned int random()
{
  static unsigned int a = 2, b = 3, c = 5, x = 7;
  return x = a * x * x + b * x + c;
}

char str[] = "0123456789";

int main()
{
  int len = strlen(str);
  char* ptr;
  unsigned int j;

  for (int i = 1; i < 1000; ++i)
  {
    j = random() % 0x7fff;
    ptr = str + j;
    if (j < 10) {
      *ptr = '7';
    }
  }

  printf("Tester 0: ");
  putchar(*(ptr - j));
  printf("\nTester 1: ");
  putchar(*(ptr - 1));
  puts(str);
}
