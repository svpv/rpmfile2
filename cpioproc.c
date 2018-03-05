// Copyright (c) 2016, 2018 Alexey Tourbin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include "errexit.h"
#include "rpmcpio.h"
#include "cpioproc.h"

struct ctx {
    pthread_mutex_t mutex;
    pthread_cond_t can_produce;
    pthread_cond_t can_consume;
    unsigned first;
    unsigned nq;
    void *jj[CPIOPROC_NQ];
    void (*proc)(void *job, void *arg);
    void *arg;
};

// Called by the worker thread.
static void *job_get(struct ctx *ctx)
{
    assert(ctx->nq > 0);
    unsigned i = ctx->first;
    ctx->first = (ctx->first + 1) % CPIOPROC_NQ;
    ctx->nq--;
    void *j = ctx->jj[i];
    return j;
}

// Called by the main thread.
static void job_put(struct ctx *ctx, void *j)
{
    assert(ctx->nq < CPIOPROC_NQ);
    unsigned i = (ctx->first + ctx->nq) % CPIOPROC_NQ;
    ctx->nq++;
    ctx->jj[i] = j;
}

// Receive a job from the main thread.
static void *cpioproc_recv(struct ctx *ctx)
{
    // lock the mutex
    int err = pthread_mutex_lock(&ctx->mutex);
    if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
    // wait until something is queued
    while (ctx->nq == 0) {
	err = pthread_cond_wait(&ctx->can_consume, &ctx->mutex);
	if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
    }
    // if they're possibly waiting to produce, let them know
    if (ctx->nq == CPIOPROC_NQ) {
	err = pthread_cond_signal(&ctx->can_produce);
	if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
    }
    // take a job from the queue
    void *j = job_get(ctx);
    // now can unlock the mutex
    err = pthread_mutex_unlock(&ctx->mutex);
    if (err) die("%s: %s", "pthread_mutex_unlock",  strerror(err));
    return j;
}

// The worker thread routine, processes the job.
static void *cpioproc_worker(void *arg)
{
    struct ctx *ctx = arg;
    while (1) {
	void *j = cpioproc_recv(ctx);
	// an exit request?
	if (j == NULL)
	    return NULL;
	// process the job
	ctx->proc(j, ctx->arg);
    }
}

// Pass a job to the worker thread.
static void cpioproc_send(struct ctx *ctx, void *j)
{
    // lock the mutex
    int err = pthread_mutex_lock(&ctx->mutex);
    if (err) die("%s: %s", "pthread_mutex_lock", strerror(err));
    // wait till there's a free slot
    while (ctx->nq == CPIOPROC_NQ) {
	err = pthread_cond_wait(&ctx->can_produce, &ctx->mutex);
	if (err) die("%s: %s", "pthread_cond_wait", strerror(err));
    }
    // if they're possibly waiting to consume, let them know
    if (ctx->nq == 0) {
	err = pthread_cond_signal(&ctx->can_consume);
	if (err) die("%s: %s", "pthread_cond_signal", strerror(err));
    }
    // put the job to the queue
    job_put(ctx, j);
    // unlock the mutex
    err = pthread_mutex_unlock(&ctx->mutex);
    if (err) die("%s: %s", "pthread_mutex_unlock", strerror(err));
}

void cpioproc(struct rpmcpio *cpio,
	void *(*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc)(void *job, void *arg),
	void *arg)
{
    pthread_t thread;
    bool running = false;
    struct ctx ctx = {
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	PTHREAD_COND_INITIALIZER,
	0, 0, { NULL, },
	proc, arg,
    };
    const struct cpioent *ent;
    while ((ent = rpmcpio_next(cpio))) {
	void *j = peek(cpio, ent, arg);
	if (!j)
	    continue;
	if (!running) {
	    int err = pthread_create(&thread, NULL, cpioproc_worker, &ctx);
	    if (err) die("%s: %s", "pthread_create", strerror(err));
	    running = true;
	}
	cpioproc_send(&ctx, j);
    }
    if (running) {
	cpioproc_send(&ctx, NULL);
	int err = pthread_join(thread, NULL);
	if (err) die("%s: %s", "pthread_join", strerror(err));
    }
}

// ex:set ts=8 sts=4 sw=4 noet:
