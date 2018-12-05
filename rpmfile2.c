#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <getopt.h>
#include <magic.h>
#include <rpmcpio.h>
#include "cpioproc.h"
#include "xwrite.h"
#include "errexit.h"

#if 100*__GLIBC__+__GLIBC_MINOR__ < 227
#include <sys/syscall.h>
#define memfd_create(name, flags) syscall(__NR_memfd_create, name, flags)
#endif

// Old versions of file(1) look at 256K buffer, modern at 1M.
#ifdef MAGIC_VERSION
#define MBUFSIZ (1<<20)
#else
#define MBUFSIZ (256<<10)
#endif

// A buffer backed by a temporary file.
struct tmpbuf {
    // Usable as MBUFSIZ, mmap'd.
    char *buf;
    // Usable as a file descriptor.
    int fd;
    // Where the file is truncated or the last byte written.
    off_t fsize;
    // ELF files are stored in full, otherwise up to MBUFSIZ.
    bool elf;
    // Also used as a cpioproc job, need to pass a few cpioent fields.
    unsigned no;
    unsigned long long size;
};

void tmpbuf_init(struct tmpbuf *t)
{
    t->fd = memfd_create("tmpbuf", 0);
    if (t->fd < 0) {
	if (errno != ENOSYS)
	    die("%s: %m", "memfd_create");
	FILE *fp = tmpfile();
	if (!fp)
	    die("%s: %m", "tmpfile");
	int fd = fileno(fp);
	assert(fd >= 0);
	fd = dup(fd);
	if (fd < 0)
	    die("%s: %m", "dup");
	fclose(fp);
    }
    t->buf = mmap(NULL, MBUFSIZ, PROT_READ | PROT_WRITE, MAP_SHARED, t->fd, 0);
    if (t->buf == MAP_FAILED)
	die("%s: %m", "mmap");
    // The mmap'd area cannot be accessed just yet, the file will be upsized
    // to at least MBUFSIZ bytes on the first call to tmpbuf_fill.
    t->fsize = 0;
}

void tmpbuf_close(struct tmpbuf *t)
{
    if (close(t->fd) < 0)
	die("%s: %m", "close");
    if (munmap(t->buf, MBUFSIZ) < 0)
	die("%s: %m", "munmap");
    t->buf = NULL;
}

void tmpbuf_fill(struct tmpbuf *t, struct rpmcpio *cpio, const struct cpioent *ent)
{
    // The first part can be copied directly into the mmap'd buffer.
    size_t part1 = ent->size < MBUFSIZ ? ent->size : MBUFSIZ;
    if (t->fsize < part1) {
	if (ftruncate(t->fd, MBUFSIZ) < 0)
	    die("%s: %m", "ftruncate");
	t->fsize = MBUFSIZ;
    }
    rpmcpio_read(cpio, t->buf, part1);
    // With size > 5, file(1) has a special ELF processing routine
    // which needs the whole file content on a file descriptor.
    bool elf = part1 > 5 && memcmp(t->buf, "\177ELF", 4) == 0;
    if (elf) {
	// For ELF, there may be part two to write on fd.
	if (ent->size > MBUFSIZ) {
	    if (lseek(t->fd, MBUFSIZ, SEEK_SET) < 0)
		die("%s: %m", "lseek");
	    char buf[BUFSIZ];
	    size_t size;
	    while ((size = rpmcpio_read(cpio, buf, sizeof buf)))
		if (!xwrite(t->fd, buf, size))
		    die("%s: %m", "write");
	}
	// File size should match directly, may need to curtail.
	if (t->fsize > ent->size)
	    if (ftruncate(t->fd, ent->size) < 0)
		die("%s: %m", "ftruncate");
	t->fsize = ent->size;
	// Rewind to the beginning.
	if (lseek(t->fd, 0, 0) < 0)
	    die("%s: %m", "lseek");
    }
    // If it's a buffer after a file, consider saving some memory.
    else if (t->fsize > 2 * MBUFSIZ)
	if (ftruncate(t->fd, MBUFSIZ) == 0)
	    t->fsize = MBUFSIZ;
    t->elf = elf;
    t->no = ent->no;
    t->size = ent->size;
}

// We have a small queue of jobs, each job needs a temporary buffer.
// Besides, the producer and consumer each need an additional temporary buffer.
#define NTMP (CPIOPROC_NQ+2)
struct tmpbuf g_tmpbuf[NTMP];

// The global libmagic handle, only used in the cpioproc thread.
magic_t g_magic;

// A single classified cpio entry, file+type.
struct ft {
    char *bn;
    char *dn;
    char *type;
    unsigned blen;
    unsigned dlen;
    unsigned tlen;
    unsigned short mode;
    bool talloc;
    char pad;
};

// passed around when generating the record for a package
struct ctx {
    const char *rpmbname;
    // total number of entries peeked/processed
    unsigned nent;
    // tmpbuf sequence/counter
    unsigned njob;
    // hardlink state
    struct { unsigned no; unsigned cnt; } hard;
    // ft[i] can be accessed without locking, provided that
    // the thread knows its index beforehand (i.e. uses ent->no)
    struct ft *ft;
};

// cpioproc callback
static void *peek(struct rpmcpio *cpio, const struct cpioent *ent, void *arg)
{
    struct ctx *ctx = arg;
    assert(ctx->nent == ent->no);
    ctx->nent++;
    struct ft *f = &ctx->ft[ent->no];
    f->mode = ent->mode;
    // Basename is always allocated.  Dirname is either reused from the
    // previous entry or placed in the same malloc chunk after basename.
    char *dn = NULL, *bn = NULL;
    size_t dlen = 0, blen = 0;
    if (*ent->fname != '/') {
	blen = ent->fnamelen;
	bn = memcpy(xmalloc(blen + 1), ent->fname, blen + 1);
    }
    else {
	bn = memrchr(ent->fname, '/', ent->fnamelen) + 1;
	dlen = bn - ent->fname;
	blen = ent->fnamelen - dlen;
	if (ent->no && f[-1].dlen == dlen
		    && memcmp(f[-1].dn, ent->fname, dlen) == 0) {
	    dn = f[-1].dn;
	    bn = memcpy(xmalloc(blen + 1), bn, blen + 1);
	}
	else {
	    bn = memcpy(xmalloc(blen + dlen + 2), bn, blen + 1);
	    dn = memcpy(bn + blen + 1, ent->fname, dlen);
	    dn[dlen] = '\0';
	}
    }
    f->bn = bn, f->blen = blen;
    f->dn = dn, f->dlen = dlen;
    // Handle hardlink sets.
    unsigned no = ent->no;
    if (!S_ISDIR(ent->mode) && ent->nlink > 1) {
	// The first hardlink in a set?
	if (ctx->hard.cnt == 0) {
	    ctx->hard.cnt = ent->nlink - 1;
	    ctx->hard.no = no;
	    return NULL;
	}
	// Non-last hardlink in a set?
	if (--ctx->hard.cnt)
	    return NULL;
	// The last hardlink in a set.  Classify all hardlinks in a set
	// following the first one as "hard link to [the first hardlink]".
	// When dirname is the same, the target shown will be relative.
	struct ft *f0 = &ctx->ft[ctx->hard.no];
	char *tabs = NULL, *trel = NULL;
	unsigned labs = 0, lrel = 0;
	for (unsigned i = ctx->hard.no + 1; i <= no; i++) {
	    struct ft *fi = &ctx->ft[i];
	    static const char HARD[] = "hard link to ";
	    if (f0->dn == fi->dn) {
		if (trel)
		    fi->talloc = false;
		else {
		    lrel = sizeof HARD - 1 + f0->blen;
		    trel = memcpy(xmalloc(lrel + 1), HARD, sizeof HARD - 1);
		    memcpy(trel + sizeof HARD - 1, f0->bn, f0->blen + 1);
		    fi->talloc = true;
		}
		fi->type = trel, fi->tlen = lrel;
	    }
	    else {
		if (tabs)
		    fi->talloc = false;
		else {
		    labs = sizeof HARD - 1 + f0->dlen + f0->blen;
		    tabs = memcpy(xmalloc(labs + 1), HARD, sizeof HARD - 1);
		    memcpy(tabs + sizeof HARD - 1, f0->dn, f0->dlen);
		    memcpy(tabs + sizeof HARD - 1 + f0->dlen, f0->bn, f0->blen + 1);
		    fi->talloc = true;
		}
		fi->type = tabs, fi->tlen = labs;
	    }
	}
	// The data coming from the last hardlink is about to be classified,
	// but the result will be put in the first hardlink's slot.
	no = ctx->hard.no;
	f = &ctx->ft[no];
	// The state of hardlink was reset with --ctx->hard.cnt.  The rpmcpio
	// library performs all the necessary validation of hardlink sets.
    }
    // file(1) only really looks at size > 1.
    if (S_ISREG(ent->mode) && ent->size > 1) {
	// Offloading tmpbuf as a job for cpioproc.
	struct tmpbuf *t = &g_tmpbuf[ctx->njob++ % NTMP];
	if (!t->buf)
	    tmpbuf_init(t);
	tmpbuf_fill(t, cpio, ent);
	t->no = no;
	return t;
    }
    // For regular files, a distinction still remains between empty and
    // non-empty files (the file size is no longer available at print time).
    if (S_ISREG(ent->mode)) {
	static char S0[] = "empty";
	static char S1[] = "very short file (no magic)";
	if (ent->size == 0)
	    f->type = S0, f->tlen = sizeof S0 - 1;
	else
	    f->type = S1, f->tlen = sizeof S1 - 1;
	f->talloc = false;
    }
    // For symbolic links, will need to print the target.
    else if (S_ISLNK(ent->mode)) {
	static const char S[] = "symbolic link to ";
	f->tlen = sizeof S - 1 + ent->size;
	char *buf = memcpy(xmalloc(f->tlen + 1), S, sizeof S - 1);
	rpmcpio_readlink(cpio, buf + sizeof S - 1, ent->size + 1);
	f->type = buf, f->talloc = true;
    }
    else // File type deducible from ent->mode at print time.
	f->type = NULL, f->tlen = 0, f->talloc = false;
    return NULL; // no job
}

// cpioproc callback, handles offloaded jobs
static void proc(void *tmpbuf, void *arg)
{
    struct tmpbuf *t = tmpbuf;
    struct ctx *ctx = arg;
    const char *type;
    if (t->elf) {
	// magic_descriptor closes the fd.
	int fd = dup(t->fd);
	if (fd < 0)
	    die("%s: %m", "dup");
	type = magic_descriptor(g_magic, fd);
    }
    else {
	size_t size = t->size < MBUFSIZ ? t->size : MBUFSIZ;
	type = magic_buffer(g_magic, t->buf, size);
    }
    struct ft *f = &ctx->ft[t->no];
    if (!(type && *type))
	die("%s: %s%s: magic failure",
	    ctx->rpmbname, f->dn ? f->dn : "", f->bn);
#define MAXTLEN 4095
    size_t tlen = strlen(type);
    if (tlen > MAXTLEN)
	die("%s: %s%s: magic type too long",
	    ctx->rpmbname, f->dn ? f->dn : "", f->bn);
    f->tlen = tlen;
    // Try to reuse the string from the previous entry.
    if (t->no && f[-1].tlen == f->tlen
	      && memcmp(f[-1].type, type, tlen) == 0)
	f->type = f[-1].type, f->talloc = false;
    else
	f->type = memcpy(xmalloc(tlen + 1), type, tlen + 1),
	    f->talloc = true;
}

// Compare two strings whose lengths are known.
static inline int strlencmp(const char *s1, size_t len1, const char *s2, size_t len2)
{
    if (len1 < len2) {
	int cmp = memcmp(s1, s2, len1);
	// If cmp == 0, still s1 < s2, because s1 is shorter.
	return cmp - (cmp == 0);
    }
    int cmp = memcmp(s1, s2, len2);
    // If cmp == 0, then s1 >= s2, because s1 may be longer.
    return cmp + ((cmp == 0) & (len1 > len2));
}

// Compare ft[] filenames for the sort routine.
static inline int fnamecmp(const char *rpmbname, struct ft *f1, struct ft *f2)
{
    assert(!f1->dn ^ !!f2->dn); // both dirnames are NULL, or both non-NULL
    if (f1->dlen == f2->dlen) {
	if (f1->dn != f2->dn) {
	    int cmp = memcmp(f1->dn, f2->dn, f1->dlen);
	    if (cmp) return cmp;
	}
	int cmp = strlencmp(f1->bn, f1->blen, f2->bn, f2->blen);
	if (cmp == 0)
	    die("%s: %s%s: filename dup", rpmbname, f1->dn ? f1->dn : "", f1->bn);
	return cmp;
    }
    // Dirname lengths are different.
    // Compare the rest of the longer dirname with the other basename.
    int cmp;
    if (f1->dlen < f2->dlen) {
	cmp = memcmp(f1->dn, f2->dn, f1->dlen);
	if (cmp) return cmp;
	cmp = strlencmp(f1->bn, f1->blen, f2->dn + f1->dlen, f2->dlen - f1->dlen);
    }
    else {
	cmp = memcmp(f1->dn, f2->dn, f2->dlen);
	if (cmp) return cmp;
	cmp = strlencmp(f1->dn + f2->dlen, f1->dlen - f2->dlen, f2->bn, f2->blen);
    }
    assert(cmp);
    return cmp;
}

// Sort ft[] by filename.  Insertion sort should suffice, because filenames
// are "almost sorted" (only hard links are grouped at the end of payload).
void sort(const char *rpmbname, struct ft ft[], size_t n)
{
    // For each item starting with the second...
    for (size_t i = 1; i < n; i++) {
	if (fnamecmp(rpmbname, &ft[i-1], &ft[i]) < 0)
	    continue;
	// move it down the array so that the first part is sorted.
	size_t j = i;
	struct ft save = ft[j];
	do
	    ft[j] = ft[j-1], j--;
	while (j && fnamecmp(rpmbname, &ft[j-1], &save) > 0);
	ft[j] = save;
    }
}

// Print a buffer to stdout.
static inline void printbuf(const void *buf, size_t size)
{
    if (fwrite_unlocked(buf, 1, size, stdout) != size)
	die("%s: %m", "fwrite");
}

// Print a single character to stdout.
static inline void printchar(unsigned char c)
{
    if (putchar_unlocked(c) != c)
	die("%s: %m", "putchar");
}

// Format a 6-digit octal number.
static inline void oct6(unsigned u, char o[6])
{
    o[0] = '0' + ((u >> 15) & 7);
    o[1] = '0' + ((u >> 12) & 7);
    o[2] = '0' + ((u >>  9) & 7);
    o[3] = '0' + ((u >>  6) & 7);
    o[4] = '0' + ((u >>  3) & 7);
    o[5] = '0' + ((u >>  0) & 7);
}

// Whether to print the middle column with file mode.
int opt_no_mode;

// Print a single entry.
void print1(struct ft *f)
{
    if (f->dn)
	printbuf(f->dn, f->dlen);
    printbuf(f->bn, f->blen);
    if (opt_no_mode)
	printchar('\t');
    else {
	// Octal mode - 5 or 6 characters, surrounded by '\t'.
	char obuf[8];
	oct6(f->mode, obuf + 1);
	// Skip the leading zero, if there is one.
	char *o = obuf + (obuf[1] == '0');
	size_t olen = 8 - (obuf[1] == '0');
	*o = obuf[7] = '\t';
	printbuf(o, olen);
    }
    // deal with type
    if (f->type)
	printbuf(f->type, f->tlen);
    else if (S_ISDIR(f->mode)) {
	const char S[] = "directory";
	printbuf(S, sizeof S - 1);
    }
    else if (S_ISCHR(f->mode)) {
	const char S[] = "character special";
	printbuf(S, sizeof S - 1);
    }
    else if (S_ISBLK(f->mode)) {
	const char S[] = "block special";
	printbuf(S, sizeof S - 1);
    }
    else if (S_ISFIFO(f->mode)) {
	const char S[] = "fifo (named pipe)";
	printbuf(S, sizeof S - 1);
    }
    else if (S_ISSOCK(f->mode)) {
	const char S[] = "socket";
	printbuf(S, sizeof S - 1);
    }
    else {
	const char S[] = "invalid mode";
	printbuf(S, sizeof S - 1);
    }
    printchar('\n');
}

void rpmfile(struct rpmcpio *cpio, unsigned nent, const char *rpmbname)
{
    struct ft *ft = reallocarray(NULL, nent, sizeof *ft);
    if (!ft)
	die("%s: cannot allocate %u file+type entries", rpmbname, nent);
    struct ctx ctx = { rpmbname, 0, 0, { 0, 0 }, ft };
    cpioproc(cpio, peek, proc, &ctx);
    nent = ctx.nent;
    // Sort by filename.
    sort(rpmbname, ft, nent);
    // Print the entries.
    for (unsigned i = 0; i < nent; i++)
	print1(&ft[i]);
    // Free data.
    for (unsigned i = 0; i < nent; i++) {
	struct ft *f = &ft[i];
	free(f->bn);
	if (f->talloc)
	    free(f->type);
    }
    free(ft);
}

// Whether to list unpackaged files found only in the header.
int opt_all;

int main(int argc, char **argv)
{
    enum { OPT_HELP = 256 };
    static const struct option longopts[] = {
	{ "help", no_argument, NULL, OPT_HELP },
	{ "no-mode", no_argument, &opt_no_mode, 1 },
	{ "all", no_argument, &opt_all, 1 },
	{ NULL },
    };
    bool usage = false;
    int c;
    while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1)
	if (c)
	    usage = true;
    if (usage) {
usage:	fprintf(stderr, "Usage: " PROG " file.rpm...\n");
	return 1;
    }
    argc -= optind, argv += optind;
    if (argc < 1) {
	warn("not enough arguments");
	goto usage;
    }
    g_magic = magic_open(0);
    if (!g_magic || magic_load(g_magic, NULL) < 0)
	die("cannot load magic db");
    // XXX --all is not yet supported properly
    opt_all = 0;
    // XXX rpmcpio_reopen is not yet implemented
    for (int i = 0; i < argc; i++) {
	const char *rpmfname = argv[i];
	unsigned nent;
	struct rpmcpio *cpio = rpmcpio_open(AT_FDCWD, rpmfname, &nent, opt_all);
	if (nent) {
	    const char *rpmbname = strrchr(rpmfname, '/');
	    rpmbname = rpmbname ? rpmbname + 1 : rpmfname;
	    rpmfile(cpio, nent, rpmbname);
	}
	rpmcpio_close(cpio);
    }
    if (fflush(stdout) != 0)
	die("%s: %m", "fflush");
    magic_close(g_magic);
    return 0;
}
