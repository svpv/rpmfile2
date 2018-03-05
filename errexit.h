#include <stdio.h>
#include <stdlib.h>

#define PROG "rpmfile2"
#define warn(fmt, args...) fprintf(stderr, PROG ": " fmt "\n", ##args)
#define die(fmt, args...) warn(fmt, ##args), exit(128) // like git

static inline void *xmalloc_(const char *func, size_t n)
{
    void *buf = malloc(n);
    if (buf == NULL)
	die("cannot allocate %zu bytes in %s()", n, func);
    return buf;
}

#define xmalloc(n) xmalloc_(__func__, n)
