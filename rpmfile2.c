#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <magic.h>
#include <frenc.h>
#include "rpmcpio.h"
#include "cpioproc.h"
#include "cacheproc.h"
#include "xwrite.h"
#include "errexit.h"

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
    // ELF files are sotred in full, otherwise up to MBUFSIZ.
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
    // The mmaped are cannot be accessed just yet, the file will be upsized
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
	// Rewrind to the beginning.
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

// file+type entry
struct ft {
    const char *name;
    const char *type;
    unsigned short mode;
    unsigned typeno;
    unsigned modeno;
};

// passed around when generating the record for a package
struct arg {
    magic_t magic;
    // tmpbuf sequence/counter
    unsigned ntmp;
    // ft[i] can be accessed without locking, provided that
    // the thread knows its beforehand (i.e. uses ent->no)
    struct ft ft[];
};

// cpioproc callback
static void *peek(struct rpmcpio *cpio, const struct cpioent *ent, void *a)
{
    struct arg *arg = a;
    struct ft *f = &arg->ft[ent->no];
    f->name = memcpy(xmalloc(ent->fnamelen + 1), ent->fname, ent->fnamelen + 1);
    f->mode = ent->mode;
    // file(1) only really looks at size > 1.
    if (S_ISREG(ent->mode) && ent->size > 1) {
	// Offloading tmpbuf as a job for cpioproc.
	struct tmpbuf *t = &g_tmpbuf[arg->ntmp++ % NTMP];
	if (!t->buf)
	    tmpbuf_init(t);
	tmpbuf_fill(t, cpio, ent);
	return t;
    }
    // Regular files and hardlinks always have types (stored in
    // rpmfile records); other kinds of files never have types.
    if (S_ISREG(ent->mode)) {
	if (ent->size == 0)
	    f->type = "empty";
	else
	    f->type = "very short file (no magic)";
    }
    else if (S_ISLNK(ent->mode)) // TODO: readlink
	f->type = "symbolic link";
    else {
	f->type = NULL;
	return NULL;
    }
    size_t len = strlen(f->type);
    f->type = memcpy(xmalloc(len + 1), f->type, len + 1);
    return NULL;
}

// cpioproc callback, handles offloaded jobs
static void proc(void *tmpbuf, void *a)
{
    struct tmpbuf *t = tmpbuf;
    struct arg *arg = a;
    const char *type;
    if (t->elf) {
	// magic_descriptor closes the fd.
	int fd = dup(t->fd);
	if (fd < 0)
	    die("%s: %m", "dup");
	type = magic_descriptor(arg->magic, fd);
    }
    else {
	size_t size = t->size < MBUFSIZ ? t->size : MBUFSIZ;
	type = magic_buffer(arg->magic, t->buf, size);
    }
    struct ft *f = &arg->ft[t->no];
    if (!type)
	die("%s: magic failure", f->name);
    size_t tlen = strlen(type);
    f->type = memcpy(xmalloc(tlen + 1), type, tlen + 1);
}

static int namecmp(const void *a1, const void *a2)
{
    const struct ft *ft1 = a1;
    const struct ft *ft2 = a2;
    return strcmp(ft1->name, ft2->name);
}

static int typecmp(const void *a1, const void *a2)
{
    const struct ft *ft1 = a1;
    const struct ft *ft2 = a2;
    // NULLs go in the end
    if (ft1->type == NULL)
	return 1 - (ft2->type == NULL);
    else if (ft2->type == NULL)
	return -1;
    return strcmp(ft1->type, ft2->type);
}

// rpmfile record format
//
//	tsize[4] fsize[4] msize[1]
//	tenc[tsize] fenc[fsize] pad[0-1]
//	mtab : mode[2]... ix[1]... | mode[2]...
//	ttab : ix[1]... | ix[2]...
//
// Little-endian tsize and fsize are the sizes of file(1) types (tenc)
// and filenames (fenc), both encoded with frenc.  When msize byte != 0,
// a compactified modes[] table is used: first goes the table of commonly
// used msize modes, and then single-byte indexes into the table (per file).
// Otherwise (msize=0), two-byte modes are per file.
//
// Then go type indexes into tenc, single byte if fsize <= 256, otherwise
// two-byte little-endian integers.  Indexes are only provided for regular
// files and symlinks (otherwise there's no magic type and no additional
// information).

void gen(const char *rpmfname, void **data, size_t *size, void *magic)
{
    unsigned nent;
    struct rpmcpio *cpio = rpmcpio_open(AT_FDCWD, rpmfname, &nent, false);
    if (nent == 0) {
	rpmcpio_close(cpio);
	return;
    }
    struct arg *arg = xmalloc(sizeof(*arg) + (nent + 1) * sizeof *arg->ft);
    struct ft *ft = arg->ft;
    arg->magic = magic;
    arg->ntmp = 0;
    memset(ft, 0, (nent + 1) * sizeof *ft);
    cpioproc(cpio, peek, proc, arg);
    rpmcpio_close(cpio);
    // actual number of entries can be smaller
    for (struct ft *p = ft; ; p++)
	if (p->name == NULL) {
	    nent = p - ft;
	    break;
	}
    if (nent == 0) {
	free(arg);
	return;
    }
    // build types blob
    qsort(ft, nent, sizeof *ft, typecmp);
    int ntypes = 0;
    void *tblob = NULL;
    size_t tblobsize = 0;
    if (ft[0].type) {
	// merge the same types
	const char **types = xmalloc(nent * sizeof(*types));
	ntypes = 1;
	types[0] = ft[0].type;
	ft[0].typeno = 0;
	for (int i = 1; i < nent; i++) {
	    if (ft[i].type == NULL)
		break;
	    if (strcmp(ft[i-1].type, ft[i].type) == 0)
		ft[i].typeno = ft[i-1].typeno;
	    else {
		types[ntypes] = ft[i].type;
		ft[i].typeno = ntypes++;
	    }
	}
	if (ntypes > 65536)
	    die("%s: too many file(1) types", xbasename(rpmfname));
	tblobsize = frenc((char **) types, ntypes, &tblob);
	if (tblobsize >= FRENC_ERROR)
	    die("frenc failed");
	free(types);
    }
    // build files blob
    qsort(ft, nent, sizeof *ft, namecmp);
    const char **names = xmalloc(nent * sizeof(*names));
    for (int i = 0; i < nent; i++)
	names[i] = ft[i].name;
    void *fblob;
    const size_t fblobsize = frenc((char **) names, nent, &fblob);
    if (fblobsize >= FRENC_ERROR)
	die("frenc failed");
    free(names);
    // can free file+type strings
    for (int i = 0; i < nent; i++)
	free((char *) ft[i].name);
    // gen the record
    size_t blobsize = 9 + tblobsize + fblobsize +
		     (9 + tblobsize + fblobsize) % 2 +
		      nent * sizeof(short) +
		      nent * (1 + (ntypes > 256));
    char *blob = xmalloc(blobsize);
    unsigned u = tblobsize; memcpy(blob + 0, &u, 4);
    unsigned v = fblobsize; memcpy(blob + 4, &v, 4);
    blob[8] = 0; // no mode maps for now
    if (tblob) {
	memcpy(blob + 9, tblob, tblobsize);
	free(tblob);
    }
    memcpy(blob + 9 + tblobsize, fblob, fblobsize);
    free(fblob);
    char *p = blob +
	 9 + tblobsize + fblobsize;
    if ((9 + tblobsize + fblobsize) % 2)
	*p++ = '\0';
    // put modes
    unsigned short *modes = (void *) p;
    for (int i = 0; i < nent; i++)
	*modes++ = ft[i].mode;
    // put type indexes
    if (ntypes > 256) {
	unsigned short *types = modes;
	for (int i = 0; i < nent; i++)
	    if (S_ISREG(ft[i].mode) || S_ISLNK(ft[i].mode))
		*types++ = ft[i].typeno;
	assert(blob + blobsize >= (char *) types);
	blobsize = (char *) types - blob;
    }
    else {
	unsigned char *types = (void *) modes;
	for (int i = 0; i < nent; i++)
	    if (S_ISREG(ft[i].mode) || S_ISLNK(ft[i].mode))
		*types++ = ft[i].typeno;
	assert(blob + blobsize >= (char *) types);
	blobsize = (char *) types - blob;
    }
    free(arg);
    *data = blob;
    *size = blobsize;
}

static inline char *oct(unsigned u, char *end)
{
    do
	*--end = '0' + (u & 7);
    while (u >>= 3);
    return end;
}

#define FWRITE(buf, size)		\
    do {				\
	if (fwrite_unlocked(buf, size, 1, stdout) != 1) \
	    die("fwrite failed");	\
    } while (0)

void put(const char *rpm, void *data0, size_t size, void *arg)
{
    (void) arg;
    if (size == 0)
	return;
    rpm = xbasename(rpm);
    if (size < 9)
	die("%s: truncated record", rpm);
    char *blob = data0;
    unsigned tblobsize; memcpy(&tblobsize, blob + 0, 4);
    unsigned fblobsize; memcpy(&fblobsize, blob + 4, 4);
    // decode types
    char **types = NULL;
    size_t ntypes = 0;
    unsigned *tlens = NULL;
    if (tblobsize) {
	ntypes = frdecl(blob + 9, tblobsize, &types, &tlens);
	if (ntypes >= FRENC_ERROR)
	    die("%s: frdec failed", rpm);
	// terminate the strings with '\n'
	for (size_t i = 0; i < ntypes; i++)
	    types[i][tlens[i]] = '\n';
    }
    // decode filenames
    char **files;
    unsigned *flens;
    size_t nfiles = frdecl(blob + 9 + tblobsize, fblobsize, &files, &flens);
    if (nfiles >= FRENC_ERROR)
	die("%s: frdec failed", rpm);
    char *p = blob +
	 9 + tblobsize + fblobsize;
    if ((9 + tblobsize + fblobsize) % 2)
	if (*p++ != '\0')
	    die("%s: invalid data (pad)", rpm);
    unsigned short *modes = (void *) p;
    union { unsigned char *t8; unsigned short *t16; } u = { (void *) (modes + nfiles) };
    for (size_t i = 0; i < nfiles; i++) {
	FWRITE(files[i], flens[i]);
	unsigned mode = modes[i];
	{
	    char buf[8];
	    buf[7] = '\t';
	    char *o = oct(mode, buf + 7);
	    *--o = '\t';
	    FWRITE(o, buf + 8 - o);
	}
	if (S_ISREG(mode) || S_ISLNK(mode)) {
	    if ((char *) u.t8 >= blob + size)
		die("%s: invalid data (type index truncated)", rpm);
	    size_t j;
	    if (ntypes > 256)
		j = *u.t16++;
	    else
		j = *u.t8++;
	    if (j >= ntypes)
		die("%s: invalid data (type index)", rpm);
	    FWRITE(types[j], tlens[j] + 1);
	}
#define PRINTLN(s) FWRITE(s "\n", sizeof(s))
	else if (S_ISDIR(mode))
	    PRINTLN("directory");
	else
	    PRINTLN("other");
    }
    free(types);
    free(files);
}

int main(int argc, char **argv)
{
    if (argc < 2)
	die("usage: rpmfile file.rpm...");
    magic_t magic = magic_open(0);
    if (!magic)
	die("cannot open magic");
    if (magic_load(magic, NULL) < 0)
	die("cannot load magic");
    cacheproc("rpmfile", NULL, argv + 1, argc - 1, gen, put, 1, magic);
    magic_close(magic);
    return 0;
}
