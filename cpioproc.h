void cpioproc_fd(struct rpmcpio *cpio,
	bool (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc)(const struct cpioent *ent, int fd, void *arg),
	void *arg);
void cpioproc_mem(struct rpmcpio *cpio,
	bool (*peek)(struct rpmcpio *cpio, const struct cpioent *ent, void *arg),
	void (*proc)(const struct cpioent *ent, char *mem, size_t size, void *arg),
	void *arg);
