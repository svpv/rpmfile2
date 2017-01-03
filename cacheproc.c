#include <stddef.h>
#include <limits.h>
#include <sys/stat.h>
#include <rpmcache.h>
#include "cacheproc.h"
#include "errexit.h"

static void proc1(struct rpmcache *C, const char *rpmfname,
	void (*gen)(const char *rpm, void **data, size_t *size, void *arg),
	void (*put)(const char *rpm, void *data, size_t size, void *arg),
	void *arg)
{
    struct stat st;
    if (C) {
	if (stat(rpmfname, &st) < 0) {
	    rpmfname = xbasename(rpmfname);
	    die("%s: %m", rpmfname);
	}
	void *data;
	int size;
	if (C && rpmcache_get(C, rpmfname, st.st_size, st.st_mtime, &data, &size)) {
	    put(rpmfname, data, size, arg);
	    free(data);
	    return;
	}
    }
    void *data = NULL;
    size_t size = 0;
    gen(rpmfname, &data, &size, arg);
    if (C) rpmcache_put(C, rpmfname, st.st_size, st.st_mtime, data, size);
    put(rpmfname, data, size, arg);
    free(data);
}

void cacheproc(const char *cache, const char *dir, char **rpms, size_t nrpms,
	void (*gen)(const char *rpm, void **data, size_t *size, void *arg),
	void (*put)(const char *rpm, void *data, size_t size, void *arg),
	bool order, void *arg)
{
    (void) order;
    char **rpms_end = rpms + nrpms;
    size_t dirlen = -1;
    struct rpmcache *C = cache && nrpms ? rpmcache_open(cache) : NULL;
    while (rpms < rpms_end) {
	const char *rpm = *rpms++;
	if (*rpm != '/' && dir) {
	    if (dirlen != (size_t) -1)
		dirlen = strlen(dir);
	    size_t len = strlen(rpm);
	    if (dirlen + len + 2 > PATH_MAX)
		die("%s: filename too long", rpm);
	    char fname[dirlen + len + 2];
	    memcpy(fname, dir, dirlen);
	    fname[dirlen] = '/';
	    memcpy(fname + dirlen + 1, rpm, len + 1);
	    proc1(C, fname, gen, put, arg);
	}
	else
	    proc1(C, rpm, gen, put, arg);
    }
    if (C)
	rpmcache_close(C);
}
