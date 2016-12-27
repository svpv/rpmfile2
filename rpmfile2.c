#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <sys/stat.h>
#include <magic.h>
#include "rpmcpio.h"
#include "cpioproc.h"
#include "errexit.h"

static unsigned peek(struct rpmcpio *cpio, const struct cpioent *ent, void *arg)
{
    (void) arg;
    // file(1) only really looks at size > 1
    if (!(S_ISREG(ent->mode) && ent->size > 1))
	return 0;
    // with size > 5, file(1) has special ELF processing routine
    // which requires the whole file with the file descriptor
    if (ent->size > 5) {
	char buf[4];
	int n = rpmcpio_peek(cpio, buf, 4);
	assert(n == 4);
	if (memcmp(buf, "\177ELF", 4) == 0)
	    return ~0U;
    }
    // older versions of file(1) look at 256K buffer, modern at 1M
#ifdef MAGIC_VERSION
    if (magic_version() >= 523)
	return 1 << 20;
#endif
    return 256 << 10;
}

static void proc_buf(const struct cpioent *ent, const void *buf, size_t size, void *arg)
{
    const char *type = magic_buffer(arg, buf, size);
    if (!type)
	die("%s: %s: magic failure", ent->rpmbname, ent->fname);
    printf("%s\t%o\t%s\n", ent->fname, ent->mode, type);
}

static void proc_file(const struct cpioent *ent, int fd, void *arg)
{
    // magic_descriptor can close fd
    fd = dup(fd);
    if (fd < 0)
	die("%s: %m", "dup");
    const char *type = magic_descriptor(arg, fd);
    close(fd);
    if (!type)
	die("%s: %s: magic failure", ent->rpmbname, ent->fname);
    printf("%s\t%o\t%s\n", ent->fname, ent->mode, type);
}

static void rpmfile(const char *rpmfname, magic_t magic)
{
    int nent;
    struct rpmcpio *cpio = rpmcpio_open(rpmfname, &nent);
    if (nent == 0) {
	assert(cpio == NULL);
	return;
    }
    cpioproc(cpio, peek, proc_buf, proc_file, magic);
    rpmcpio_close(cpio);
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
    for (int i = 1; i < argc; i++)
	rpmfile(argv[i], magic);
    magic_close(magic);
    return 0;
}
