#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
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
    struct cpioent ent;
    char fname[PATH_MAX];
};

struct job {
    pthread_mutex_t mutex;
    pthread_cond_t can_produce;
    pthread_cond_t can_consume;
    bool has_item;
    struct tmpfile *tmpf;
    void (*proc_fd)(const struct cpioent *ent, int fd, void *arg);
    void (*proc_mem)(const struct cpioent *ent, char *mem, size_t size, void *arg);
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
	if (job->proc_fd)
	    job->proc_fd(&tmpf->ent, tmpf->fd, job->arg);
	else
	    job->proc_mem(&tmpf->ent, tmpf->mem, tmpf->ent.size, job->arg);
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

#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>

static void cpioproc_tmpfile(struct tmpfile *tmpf, size_t size, bool need_fd)
{
    if (tmpf->fp) {
	if (need_fd && lseek(tmpf->fd, 0, 0) < 0)
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
    // If they need the fd, it must be truncated to the exact size
    if (tmpf->fsize < size) {
	int err = posix_fallocate(tmpf->fd, 0, size);
	if (err) die("%s: %s: posix_fallocate (%zu bytes): %s",
		     tmpf->ent.rpmbname, tmpf->ent.fname, size, strerror(err));
	tmpf->fsize = size;
    }
    else if (need_fd && tmpf->fsize > size) {
	if (ftruncate(tmpf->fd, size) < 0)
	    die("%s: %m", "ftruncate");
	tmpf->fsize = size;
    }
    if (tmpf->msize >= size)
	return;
    if (tmpf->mem && munmap(tmpf->mem, tmpf->msize) < 0)
	die("%s: %m", "munmap");
    tmpf->mem = mmap(NULL, size,
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, tmpf->fd, 0);
    if (tmpf->mem == MAP_FAILED)
	die("%s: %s: mmap (%zu bytes): %m", tmpf->ent.rpmbname, tmpf->ent.fname, size);
    tmpf->msize = size;
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

static void cpioproc(struct rpmcpio *cpio,
	bool (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc_fd)(const struct cpioent *ent, int fd, void *arg),
	void (*proc_mem)(const struct cpioent *ent, char *mem, size_t size, void *arg),
	void *arg)
{
    const struct cpioent *ent;
    pthread_t thread;
    struct job job = {
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	0, NULL,
	proc_fd, proc_mem, arg,
    };
    struct tmpfile tmpff[2];
    tmpff[0].fp = tmpff[1].fp = NULL;
    unsigned nfiles = 0;
    while ((ent = rpmcpio_next(cpio))) {
	if (!peek(cpio, ent, arg))
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
	// create or resize tmpfile
	cpioproc_tmpfile(tmpf, ent->size, proc_fd);
	// copy file data
	int n = rpmcpio_read(cpio, tmpf->mem, ent->size + 1);
	assert(n == (int) ent->size);
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

void cpioproc_fd(struct rpmcpio *cpio,
	bool (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc)(const struct cpioent *ent, int fd, void *arg),
	void *arg)
{
    cpioproc(cpio, peek, proc, NULL, arg);
}

void cpioproc_mem(struct rpmcpio *cpio,
	bool (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc)(const struct cpioent *ent, char *mem, size_t size, void *arg),
	void *arg)
{
    cpioproc(cpio, peek, NULL, proc, arg);
}
