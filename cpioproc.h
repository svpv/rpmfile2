void cpioproc(struct rpmcpio *cpio,
	// peek returns: 0 - skip the entry;
	// size - buffer size to process;
	// ~OU - process the whole file via fd
	unsigned (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc_buf)(const struct cpioent *ent, const void *buf, size_t size, void *arg),
	void (*proc_file)(const struct cpioent *ent, int fd, void *arg),
	void *arg);
