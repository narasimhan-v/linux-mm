// SPDX-License-Identifier: GPL-2.0-only
/*
 * random kernel bug collection
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/wait.h>

#define THREADS 10

static void *safe_malloc(size_t size)
{
	void *ptr = malloc(size);

	if (!ptr)
		fprintf(stderr, "malloc %zu: %s\n", size, strerror(errno));

	return ptr;
}

static void print_start(const char *name)
{
	printf("start: %s\n", name);
}

static DIR *safe_opendir(char *path)
{
	DIR *dir = opendir(path);

	if (!dir)
		fprintf(stderr, "opendir %s: %s\n", path, strerror(errno));

	return dir;
}

static FILE *safe_fopen(char *path, const char *mode)
{
	FILE *fp = fopen(path, mode);

	if (!fp)
		fprintf(stderr, "fopen %s: %s\n", path, strerror(errno));

	return fp;
}

static void *thread_mmap(void *data)
{
	char *ptr;
	long i;
	int pagesz = getpagesize();
	long length = (long)data;

	ptr = mmap(NULL, length, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	for (i = 0; i < length; i += pagesz)
		ptr[i] = '\a';

	return NULL;
}

static void child_mmap(size_t size)
{
	pthread_t *thread;
	int i;

	thread = safe_malloc(sizeof(pthread_t) * THREADS);
	if (!thread)
		return;

	for (i = 0; i < THREADS; i++) {
		printf("info: mmap %d%% memory: %zu\n", THREADS,
		       size / THREADS);

		if (pthread_create(&thread[i], NULL, thread_mmap,
				   (void *)(size / THREADS)))
			perror("pthread_create");
	}
	for (i = 0; i < THREADS; i++)
		pthread_join(thread[i], NULL);

	free(thread);
}

/* Allocate memory and mmap them. */
static void alloc_mmap(size_t size)
{
	pid_t pid;

	print_start(__func__);
	switch(pid = fork()) {
	case 0:
		child_mmap(size);
		exit(0);
	case -1:
		perror("fork");
		return;
	default:
		break;
	}
	wait(NULL);
}

/* Offline and online all memory. */
static void hotplug_memory()
{
	char *base = "/sys/devices/system/memory";
	char path[PATH_MAX];
	DIR *dir, *section;
	struct dirent *memory;

	print_start(__func__);
	dir = safe_opendir(base);
	if (!dir)
		return;

	while ((memory = readdir(dir))) {
		struct dirent *final;

		if (!strcmp (memory->d_name, "."))
			continue;
		if (!strcmp (memory->d_name, ".."))
			continue;
		if (memory->d_type != DT_DIR)
			continue;
		snprintf(path, PATH_MAX, "%s/%s", base, memory->d_name);
		section = safe_opendir(path);
		if (!section)
			return;

		while ((final = readdir(section))) {
			FILE *fp;

			if (!strcmp (final->d_name, "state"))
				continue;
			snprintf(path, PATH_MAX, "%s/%s/state", base,
				 memory->d_name);
			fp = fopen(path, "w+");
			if (!fp)
				continue;
			if (fwrite("offline", 8, 1, fp)) {
				fflush(fp);
				fwrite("online", 7, 1, fp);
			}
			fclose(fp);
			break;
		}
		closedir(section);
	}
	closedir(dir);
}

int main()
{
	long free_size;
	size_t len = 0;
	FILE *fp = safe_fopen("/proc/meminfo", "r");
	char *line = NULL;

	if (!fp)
		return 1;

	/* MemFree is the second line. */
	getline(&line, &len, fp);
	getline(&line, &len, fp);
	sscanf(line, "%*s%ld%*s", &free_size);

	free(line);
	fclose(fp);

	/* Allocate a bit more to trigger swapping/OOM. */
	alloc_mmap(free_size * 1024 * 1.2);
	hotplug_memory();

	return 0;
}
