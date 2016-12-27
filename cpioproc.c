#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <limits.h>
#include "errexit.h"
#include "rpmcpio.h"

// We manage a few temporary files: while one of them is processed
// by the worker, the main thread writes another.  A temporary file
// also provides additional information on where it comes from and
// how it should be processed.
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

// Actually we have a small queue of temporary files
#define NQ 2

struct job {
    pthread_mutex_t mutex;
    pthread_cond_t can_produce;
    pthread_cond_t can_consume;
    int nq;
    struct tmpfile *tmpff[NQ];
    void (*proc_buf)(const struct cpioent *ent, const void *buf, size_t size, void *arg);
    void (*proc_file)(const struct cpioent *ent, int fd, void *arg);
    void *arg;
};

// The main thread reads cpio, this worker thread processes temporary files
static void *cpioproc_worker(void *ctx)
{
    struct job *job = ctx;
    while (1) {
	// lock the mutex
	int err = pthread_mutex_lock(&job->mutex);
	if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
	// wait until something is queued
	while (job->nq == 0) {
	    err = pthread_cond_wait(&job->can_consume, &job->mutex);
	    if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
	}
	// take the jobs from the queue
	int nq = job->nq;
	struct tmpfile *tmpff[NQ];
	memcpy(tmpff, job->tmpff, sizeof tmpff);
	job->nq = 0;
	// if they're possibly waiting to produce, let them know
	if (nq == NQ) {
	    err = pthread_cond_signal(&job->can_produce);
	    if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
	}
	// now can unlock the mutex
	err = pthread_mutex_unlock(&job->mutex);
	if (err) die("%s: %s", "pthread_mutex_unlock",  strerror(err));
	// process the jobs
	for (int i = 0; i < nq; i++) {
	    struct tmpfile *tmpf = tmpff[i];
	    // an exit request?
	    if (tmpf == NULL)
		return NULL;
	    // process the job
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
	}
    }
}

static void cpioproc_signal(struct job *job, struct tmpfile *tmpf)
{
    int err = pthread_mutex_lock(&job->mutex);
    if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
    while (job->nq == NQ) {
	err = pthread_cond_wait(&job->can_produce, &job->mutex);
	if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
    }
    int nq = job->nq;
    job->tmpff[job->nq++] = tmpf;
    // if they're possibly waiting to consume, let them know
    if (nq == 0) {
	err = pthread_cond_signal(&job->can_consume);
	if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
    }
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
	0, { NULL, },
	proc_buf, proc_file, arg,
    };
    // Getting the number of temporary files right is no small matter.
    // Let's see, the worker can process two files, cpioproc can queue
    // two more files and be writing yet another one.
#define NTMP (2 * NQ + 1)
    struct tmpfile tmpff[NTMP];
    for (int i = 0; i < NTMP; i++)
	tmpff[i].fp = NULL;
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
	struct tmpfile *tmpf = &tmpff[nfiles++ % NTMP];
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
	for (int i = 0; i < NTMP; i++)
	    cpioproc_close_tmpfile(&tmpff[i]);
    }
}
