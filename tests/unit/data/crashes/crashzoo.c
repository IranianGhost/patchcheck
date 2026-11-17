/* Deliberately faulty program used only to record real sanitizer/libc
   diagnostics for analysis unit tests. Usage: crashzoo CASE N (N = 16). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))
int global_buf[4];
char *volatile sink;

NOINLINE static void heap_overflow(int n) { char *p = malloc(8); memset(p, 'A', n); sink = p; putchar(sink[0]); free(p); }
NOINLINE static void stack_overflow(int n) { char buf[8]; volatile char *q = buf; for (int i = 0; i < n * 4; i++) q[i] = 'A'; sink = buf; }
NOINLINE static void stack_pointer(int n) { char buf[8]; char *volatile q = buf; for (int i = 0; i < n * 4; i++) q[i] = 'A'; sink = buf; }
NOINLINE static void use_after_free(int n) { char *p = malloc(n); sink = p; free(p); sink[0] = 1; }
NOINLINE static void double_free(int n) { char *p = malloc(n); sink = p; free(p); free(sink); }
NOINLINE static int null_deref(int *p) { return *p; }
NOINLINE static int divide(int a, int b) { return a / b; }
NOINLINE static int global_overflow(int i) { int *volatile q = global_buf; return q[i]; }
NOINLINE static int array_index(int i) { return global_buf[i]; }

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "";
    int n = argc > 2 ? atoi(argv[2]) : 16;
    if (!strcmp(c, "heap")) heap_overflow(n);
    else if (!strcmp(c, "stack")) stack_overflow(n);
    else if (!strcmp(c, "stackp")) stack_pointer(n);
    else if (!strcmp(c, "uaf")) use_after_free(n);
    else if (!strcmp(c, "double")) double_free(n);
    else if (!strcmp(c, "null")) return null_deref((int *)(long)(n - 16));
    else if (!strcmp(c, "div")) return divide(n * 7, n - 16);
    else if (!strcmp(c, "global")) return global_overflow(n - 12);
    else if (!strcmp(c, "index")) return array_index(n - 12);
    return 0;
}
