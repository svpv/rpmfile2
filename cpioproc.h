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

#pragma once

// rpmcpio.h
struct rpmcpio;
struct cpioent;

// Process cpio entries.
// Heavy processing operations can be offloaded to a separate thread.
// Moreover, the processor maintains a small queue of offloaded jobs.
#define CPIOPROC_NQ 4

void cpioproc(struct rpmcpio *cpio,
	// Called for each entry.  If an entry is heavy, it can be
	// packaged into and returned as a "job" for further processing.
	void *(*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	// Called in another thread to process the jobs returned by peek().
	void (*proc)(void *job, void *arg),
	void *arg);
