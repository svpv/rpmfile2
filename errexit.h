#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define warn_(func, fmt, args...) \
    fprintf(stderr, "%s: %s: " fmt "\n", \
	    program_invocation_short_name, func, ##args); \

#define die_(func, fmt, args...) \
    do { \
	warn_(func, fmt, ##args); \
	exit(128); \
    } while (0)

#define warn(fmt, args...) warn_(__func__, fmt, ##args)
#define  die(fmt, args...)  die_(__func__, fmt, ##args)

static inline void *xmalloc_(const char *func, size_t n)
{
    void *buf = malloc(n);
    if (buf == NULL)
	die_(func, "cannot allocate %zu bytes", n);
    return buf;
}

#define xmalloc(n) xmalloc_(__func__, n)

static inline const char *xbasename_(const char *func, const char *fname)
{
    const char *bn = strrchr(fname, '/');
    bn = bn ? bn + 1 : fname;
    const char *p = bn;
    while (*p == '.')
	p++;
    if (*p == '\0')
	die_(func, "%s: cannot make basename", fname);
    return bn;
}

#define xbasename(fname) xbasename_(__func__, fname)
