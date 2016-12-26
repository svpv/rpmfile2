#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <limits.h>
#include "errexit.h"
#include "rpmcpio.h"

// We manage two temporary files: while one of them is processed
// by the worker, the main thread writes another
struct tmpfile {
    FILE *fp;
    int fd;
    size_t fsize;
    char *mem;
    size_t msize;
    bool need_file;
    size_t need_size;
    struct cpioent ent;
    char fname[PATH_MAX];
};

struct job {
    pthread_mutex_t mutex;
    pthread_cond_t can_produce;
    pthread_cond_t can_consume;
    bool has_item;
    struct tmpfile *tmpf;
    void (*proc_buf)(const struct cpioent *ent, const void *buf, size_t size, void *arg);
    void (*proc_file)(const struct cpioent *ent, int fd, void *arg);
    void *arg;
};

// The main thread reads cpio, this worker thread processes temporary file
static void *cpioproc_worker(void *ctx)
{
    struct job *job = ctx;
    int err = pthread_mutex_lock(&job->mutex);
    if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
    while (1) {
	while (!job->has_item) {
	    err = pthread_cond_wait(&job->can_consume, &job->mutex);
	    if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
	}
	struct tmpfile *tmpf = job->tmpf;
	if (tmpf == NULL)
	    break;
	if (tmpf->need_file) {
	    assert(job->proc_file);
	    // full file written
	    assert(tmpf->fsize == tmpf->ent.size);
	    job->proc_file(&tmpf->ent, tmpf->fd, job->arg);
	}
	else {
	    assert(job->proc_buf);
	    // trailing null byte, see below
	    assert(tmpf->msize > tmpf->need_size);
	    job->proc_buf(&tmpf->ent, tmpf->mem, tmpf->need_size, job->arg);
	}
	job->has_item = 0;
	err = pthread_cond_signal(&job->can_produce);
	if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
    }
    err = pthread_mutex_unlock(&job->mutex);
    if (err) die("%s: %s", "pthread_mutex_unlock",  strerror(err));
    return NULL;
}

static void cpioproc_signal(struct job *job, struct tmpfile *tmpf)
{
    int err = pthread_mutex_lock(&job->mutex);
    if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
    while (job->has_item) {
	err = pthread_cond_wait(&job->can_produce, &job->mutex);
	if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
    }
    job->tmpf = tmpf;
    job->has_item = 1;
    err = pthread_cond_signal(&job->can_consume);
    if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
    err = pthread_mutex_unlock(&job->mutex);
    if (err) die("%s: %s", "pthread_mutex_unlock", strerror(err));
}

#include <fcntl.h>
#include <sys/mman.h>

static void cpioproc_tmpfile(struct tmpfile *tmpf, size_t need_size)
{
    bool need_file = tmpf->need_file = need_size == ~0U;
    if (need_size > tmpf->ent.size)
	need_size = tmpf->ent.size;
    tmpf->need_size = need_size;
    assert(need_size > 0);
    assert(need_size < ~0U);
    if (tmpf->fp) {
	if (need_file && lseek(tmpf->fd, 0, 0) < 0)
	    die("%s: %m", "lseek");
    }
    else {
	tmpf->fp = tmpfile();
	if (tmpf->fp == NULL)
	    die("%s: %m", "tmpfile");
	tmpf->fd = fileno(tmpf->fp);
	assert(tmpf->fd >= 0);
	tmpf->mem = NULL;
	tmpf->msize = 0;
	tmpf->fsize = 0;
    }
    // If they need the fd, it must be truncated to the exact size.
    // Otherwise, add trailing null byte to protect string functions.
    bool nullbyte = !need_file;
    if (tmpf->fsize < need_size + nullbyte) {
	int err = posix_fallocate(tmpf->fd, 0, need_size + nullbyte);
	if (err) die("%s: %s: posix_fallocate (%zu bytes): %s",
		     tmpf->ent.rpmbname, tmpf->ent.fname,
		     need_size + nullbyte, strerror(err));
	tmpf->fsize = need_size + nullbyte;
    }
    else if (need_file && tmpf->fsize > need_size) {
	if (ftruncate(tmpf->fd, need_size) < 0)
	    die("%s: %m", "ftruncate");
	tmpf->fsize = need_size;
    }
    if (tmpf->msize >= need_size + nullbyte) {
ret:	if (nullbyte)
	    tmpf->mem[need_size] = '\0';
	return;
    }
    if (tmpf->mem && munmap(tmpf->mem, tmpf->msize) < 0)
	die("%s: %m", "munmap");
    tmpf->mem = mmap(NULL, need_size + nullbyte,
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, tmpf->fd, 0);
    if (tmpf->mem == MAP_FAILED)
	die("%s: %s: mmap (%zu bytes): %m",
	    tmpf->ent.rpmbname, tmpf->ent.fname, need_size + nullbyte);
    tmpf->msize = need_size + nullbyte;
    goto ret;
}

static void cpioproc_close_tmpfile(struct tmpfile *tmpf)
{
    if (tmpf->fp == NULL)
	return;
    if (fclose(tmpf->fp) != 0)
	die("%s: %m", "fclose");
    if (tmpf->mem && munmap(tmpf->mem, tmpf->msize) < 0)
	die("%s: %m", "munmap");
}

#include <sys/stat.h>
#include "cpioproc.h"

void cpioproc(struct rpmcpio *cpio,
	unsigned (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc_buf)(const struct cpioent *ent, const void *buf, size_t size, void *arg),
	void (*proc_file)(const struct cpioent *ent, int fd, void *arg),
	void *arg)
{
    const struct cpioent *ent;
    pthread_t thread;
    struct job job = {
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	0, NULL,
	proc_buf, proc_file, arg,
    };
    struct tmpfile tmpff[2];
    tmpff[0].fp = tmpff[1].fp = NULL;
    unsigned nfiles = 0;
    while ((ent = rpmcpio_next(cpio))) {
	unsigned size = peek(cpio, ent, arg);
	if (!size)
	    continue;
	if (!S_ISREG(ent->mode)) {
	    warn("%s: %s: will not process non-regular file", ent->rpmbname, ent->fname);
	    continue;
	}
	if (ent->size == 0) {
	    warn("%s: %s: will not process empty file", ent->rpmbname, ent->fname);
	    continue;
	}
	if (nfiles == 0) {
	    int err = pthread_create(&thread, NULL, cpioproc_worker, &job);
	    if (err) die("%s: %s", "pthread_create", strerror(err));
	}
	// select tmpfile
	struct tmpfile *tmpf = &tmpff[nfiles++ % 2];
	// copy ent and fname (will be overwritten on the next iteration)
	assert(ent->fnamelen < sizeof tmpf->fname);
	memcpy(&tmpf->ent, ent, sizeof(*ent) + ent->fnamelen + 1);
	// create or resize tmpfile (also handles ~0U case)
	cpioproc_tmpfile(tmpf, size);
	// copy file data
	if (size > ent->size)
	    size = ent->size;
	int n = rpmcpio_read(cpio, tmpf->mem, size + (size == ent->size));
	assert(n == (int) size);
	// feed to worker
	cpioproc_signal(&job, tmpf);
    }
    if (nfiles) {
	cpioproc_signal(&job, NULL);
	int err = pthread_join(thread, NULL);
	if (err) die("%s: %s", "pthread_join", strerror(err));
	cpioproc_close_tmpfile(&tmpff[0]);
	cpioproc_close_tmpfile(&tmpff[1]);
    }
}
