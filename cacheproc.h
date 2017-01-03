void cacheproc(const char *cache, const char *dir, char **rpms, size_t nrpms,
	void (*gen)(const char *rpm, void **data, size_t *size, void *arg),
	void (*put)(const char *rpm, void *data, size_t size, void *arg),
	bool order, void *arg);
