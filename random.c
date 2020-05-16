// SPDX-License-Identifier: GPL-2.0-only
/*
 * random kernel bug collection
 *
 * Accept an additional argument to trigger a specific bug by number.
 * 1: trigger swapping/OOM, and then offline all memory.
 * 2: migrate hugepages while soft offlining, and then offline all memory.
 * 3: migrate KSM pages repetitively.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MADV_SOFT_OFFLINE 101
#define MPOL_BIND 2
#define MPOL_MF_MOVE_ALL (1 << 2)
#define NR_LOOP 1000
#define NR_NODE 4096
#define NR_PAGE 20
#define NR_THREAD 10

static void print_start(const char *name)
{
	printf("- start: %s\n", name);
}

static void *safe_malloc(size_t length)
{
	void *addr = malloc(length);

	if (!addr)
		fprintf(stderr, "malloc %zu: %s\n", length, strerror(errno));

	return addr;
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

static void *safe_mmap(void *addr, size_t length, int prot, int flags, int fd,
		       off_t offset)
{
	void *ptr;

	ptr = mmap(addr, length, prot, flags, fd, offset);
	if (ptr == MAP_FAILED)
		fprintf(stderr, "mmap %zu: %s\n", length, strerror(errno));

	return ptr;
}

static int safe_munmap(void *addr, size_t length)
{
	if (munmap(addr, length)) {
		fprintf(stderr, "munmap %zu: %s\n", length, strerror(errno));

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static long safe_mbind(void *addr, unsigned long length, int mode,
		       const unsigned long *nodemask, unsigned long maxnode,
		       unsigned flags)
{
	if (syscall(__NR_mbind, (long)addr, length, mode, (long)nodemask,
		    maxnode, flags)) {
		perror("mbind");

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int safe_mlock(const void *addr, size_t length)
{
	if (mlock(addr, length)) {
		fprintf(stderr, "munmap %zu: %s\n", length, strerror(errno));

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static long safe_migrate_pages(int pid, unsigned long max_node,
			       const unsigned long *old_nodes,
			       const unsigned long *new_nodes)
{
	if (syscall(__NR_migrate_pages, pid, max_node, old_nodes,
		    new_nodes) < 0) {
		perror("migrate_pages");

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int safe_fread(void *ptr, size_t size, size_t item, FILE *fp)
{
	fread(ptr, sizeof(ptr), item, fp);
	if (ferror(fp)) {
		perror("fread");
		fclose(fp);

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int safe_fwrite(void *ptr, size_t size, size_t item, FILE *fp)
{
	if (!fwrite(ptr, size, item, fp)) {
		perror("fwrite");
		fclose(fp);

		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static size_t get_meminfo(char *field)
{
	FILE *fp = safe_fopen("/proc/meminfo", "r");
	char *line = NULL;
	char key[100];
	size_t length = 0;
	size_t value = -1;

	if (!fp)
		return -1;

	while (getline(&line, &length, fp) != -1) {
		sscanf(line, "%s%zu%*s", key, &value);
		if (!strcmp(field, key))
			goto out;
	}
	fprintf(stderr, "- fail: no %s in meminfo.\n", field);
out:
	free(line);
	fclose(fp);

	return value;
}

static long set_node_huge(int node, long size, size_t huge_size)
{
	FILE *fp;
	char path[PATH_MAX];
	char value[100];
	char *base = "/sys/devices/system/node";
	long save;

	snprintf(path, sizeof(path),
		 "%s/node%d/hugepages/hugepages-%zukB/nr_hugepages",
		 base, node, huge_size);
	fp = safe_fopen(path, "w+");
	if (!fp)
		return -1;

	if (safe_fread(value, sizeof(value), 1, fp))
		return -1;

	save = atol(value);
	if (size < 0)
		goto out;

	snprintf(value, sizeof(value), "%ld", size);
	if (safe_fwrite(value, sizeof(value), 1, fp))
		return -1;
out:
	fclose(fp);

	return save;
}

static int mmap_offline_node_huge(size_t length)
{
	char *addr;
	int i, code;

	for (i = 0; i < NR_LOOP; i++) {
		addr = mmap(NULL, length, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
		if (addr == MAP_FAILED) {
			if (i == 0 || errno != ENOMEM) {
				perror("mmap");

				return EXIT_FAILURE;
			}
			usleep(1000);
			continue;
		}
		memset(addr, 0, length);

		code = madvise(addr, length, MADV_SOFT_OFFLINE);
		if(safe_munmap(addr, length))
			return EXIT_FAILURE;

		/* madvise() could return >= 0 on success. */
		if (code < 0 && errno != EBUSY) {
			perror("madvise");

			return EXIT_FAILURE;
		}
	}
	printf("- pass: %s\n", __func__);
	return EXIT_SUCCESS;
}

static int loop_move_pages(int node1, int node2, size_t length)
{
	int pagesz = getpagesize();
	int nr_pages = length / pagesz;
	int i, j;
	int *nodes = safe_malloc(sizeof(int) * nr_pages);
	int *status = safe_malloc(sizeof(int) * nr_pages);
	void **pages = safe_malloc(sizeof(char *) * nr_pages);
	void *addr;
	pid_t ppid = getppid();

	if (!pages || !nodes || !status)
		goto out;

	addr = safe_mmap(NULL, length, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (addr == MAP_FAILED)
		goto out;

	if (munmap(addr, length))
		goto out;

	for (i = 0; i < nr_pages; i++)
		pages[i] = addr + i * pagesz;

	for (i = 0; ; i++) {
		for (j = 0; j < nr_pages; j++) {
			nodes[j] = (i % 2) ? node2 : node1;
			status[j] = 0;
		}
		/* move_pages() could return >= 0 on success. */
		if(syscall(__NR_move_pages, ppid, nr_pages, pages,
			   nodes, status, MPOL_MF_MOVE_ALL) < 0) {
			if (errno == ENOMEM)
				continue;
			perror("move_pages");
			goto out;
		}
	}
out:
	free(pages);
	free(nodes);
	free(status);

	return EXIT_FAILURE;
}

static int mmap_bind_node_huge(int node, size_t length)
{
	void *addr;
	unsigned long mask[NR_NODE] = { 0 };

	printf("- info: mmap and free %zu bytes hugepages on node %d\n",
	       length, node);
	addr = safe_mmap(NULL, length, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (addr == MAP_FAILED)
		return EXIT_FAILURE;

	mask[0] = 1 << node;
	if (safe_mbind(addr, length, MPOL_BIND, mask, NR_NODE, 0))
		return EXIT_FAILURE;

	if (safe_mlock(addr, length))
		return EXIT_FAILURE;

	if (safe_munmap(addr, length))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int get_numa(int *node1, int *node2)
{
	char *line = NULL;
	size_t length = 0;
	FILE *fp;

	fp = safe_fopen("/sys/devices/system/node/has_memory", "r");
	if (!fp) {
		fprintf(stderr, "- fail: it requires NUMA nodes.\n");

		return EXIT_FAILURE;
	}
	*node1 = -1;
	*node2 = -1;
	getline(&line, &length, fp);
	sscanf(line, "%d%*c%d", node1, node2);
	free(line);
	fclose(fp);

	if (*node1 == -1 || *node2 == -1) {
		fprintf(stderr, "- fail: it requires 2 NUMA nodes.\n");

		return EXIT_FAILURE;
	}
	printf("- info: use NUMA nodes %d,%d.\n", *node1, *node2);

	return EXIT_SUCCESS;
}

static long read_value(char *path)
{
	FILE *fp = safe_fopen(path, "r");
	char value[100];

	if (!fp)
		return -1;

	if (safe_fread(value, sizeof(value), 1, fp)) {
		fclose(fp);

		return -1;
	}
	fclose(fp);

	return atol(value);
}

static int write_value(char *path, long value)
{
	FILE *fp = safe_fopen(path, "w");
	char s[100];

	if (!fp)
		return -1;

	snprintf(s, sizeof(s), "%ld", value);
	if (safe_fwrite(s, sizeof(s), 1, fp)) {
		fclose(fp);

		return EXIT_FAILURE;
	}
	fclose(fp);

	return EXIT_SUCCESS;
}

static int scan_ksm()
{
	long scans, full_scans;
	int count = 0;
	int run;
	char *base = "/sys/kernel/mm/ksm";
	char path[PATH_MAX];
	char value[100];
	FILE *fp;

	snprintf(path, sizeof(path), "%s/run", base);
	fp = safe_fopen(path, "w+");
	if (!fp)
		return -1;

	if (safe_fread(value, sizeof(value), 1, fp))
		return -1;

	run = atoi(value);
	if (run != 1 && safe_fwrite("1", 2, 1, fp))
		return -1;

	fclose(fp);
	snprintf(path, sizeof(path), "%s/full_scans", base);
	scans = read_value(path);
	if (scans < 0)
		goto out;
	/*
	 * The current scan is already in progress so we can't guarantee that
	 * the get_user_pages() is called on every existing rmap_item if we
	 * only waited for the remaining part of the scan.
	 *
	 * The actual merging happens after the unstable tree has been built so
	 * we need to wait at least two full scans to guarantee merging, hence
	 * wait full_scans to increment by 3 so that at least two full scans
	 * will run.
	 */
	full_scans = scans + 3;
	while (scans < full_scans) {
		sleep(1);
		count++;
		scans = read_value(path);
		if (scans < 0)
			goto out;
	}
	printf("- info: KSM takes %ds to run two full scans.\n", count);

	return run;
out:
	snprintf(value, sizeof(value), "%d", run);
	safe_fwrite(value, sizeof(value), 1, fp);

	return -1;
}

static void *thread_mmap(void *data)
{
	char *addr;
	size_t i;
	size_t length = (size_t)data;

	addr = mmap(NULL, length, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");

		return NULL;
	}
	for (i = 0; i < length; i += getpagesize())
		addr[i] = '\a';

	return NULL;
}

static void loop_mmap(size_t length)
{
	pthread_t *thread;
	int i;
	size_t size = length / NR_THREAD;

	thread = safe_malloc(sizeof(pthread_t) * NR_THREAD);
	if (!thread)
		return;

	for (i = 0; i < NR_THREAD; i++) {
		printf("- info: mmap %d%% memory: %zu\n", 100 / NR_THREAD,
		       size);
		if (pthread_create(&thread[i], NULL, thread_mmap,
				   (void *)size))
			perror("pthread_create");
	}
	for (i = 0; i < NR_THREAD; i++)
		pthread_join(thread[i], NULL);

	free(thread);
}

/* Allocate memory and mmap them. */
static int alloc_mmap(size_t length)
{
	pid_t pid;

	print_start(__func__);
	switch(pid = fork()) {
	case 0:
		loop_mmap(length * 1024);

		exit(EXIT_SUCCESS);
	case -1:
		perror("- fail: fork");

		return EXIT_FAILURE;
	default:
		break;
	}
	wait(NULL);

	return EXIT_SUCCESS;
}

/* Offline and online all memory. */
static int hotplug_memory()
{
	char *base = "/sys/devices/system/memory";
	char path[PATH_MAX];
	DIR *dir, *section;
	struct dirent *memory;

	print_start(__func__);
	dir = safe_opendir(base);
	if (!dir)
		return EXIT_FAILURE;

	while ((memory = readdir(dir))) {
		struct dirent *final;

		if (!strcmp (memory->d_name, "."))
			continue;
		if (!strcmp (memory->d_name, ".."))
			continue;
		if (memory->d_type != DT_DIR)
			continue;
		snprintf(path, sizeof(path), "%s/%s", base, memory->d_name);
		section = safe_opendir(path);
		if (!section) {
			closedir(dir);

			return EXIT_FAILURE;
		}
		while ((final = readdir(section))) {
			FILE *fp;

			if (!strcmp (final->d_name, "state"))
				continue;
			snprintf(path, sizeof(path), "%s/%s/state", base,
				 memory->d_name);
			fp = fopen(path, "w+");
			if (!fp)
				continue;

			if (safe_fwrite("offline", 8, 1, fp)) {
				fflush(fp);
				if (safe_fwrite("online", 7, 1, fp)) {
					fclose(fp);
					closedir(section);
					closedir(dir);

					return EXIT_FAILURE;
				}
			}
			fclose(fp);
			break;
		}
		closedir(section);
	}
	closedir(dir);

	return EXIT_SUCCESS;
}

/* Migrate hugepages while soft offlining. */
static int migrate_huge_offline(size_t free_size)
{
	size_t huge_size, length;
	int node1, node2, status;
	int code = EXIT_SUCCESS;
	long save1, save2;
	pid_t pid;

	print_start(__func__);
	if (get_numa(&node1, &node2))
		return EXIT_FAILURE;

	huge_size = get_meminfo("Hugepagesize:");
	if (huge_size < 0)
		return EXIT_FAILURE;

	/* 4 pages are required to trigger the bug. */
	if (8 * huge_size > free_size) {
		fprintf(stderr,
			"- fail: not enough memory for 8 hugepages.\n");

		return EXIT_FAILURE;
	}
	save1 = set_node_huge(node1, -1, huge_size);
	if (save1 < 0)
		return EXIT_FAILURE;

	save2 = set_node_huge(node2, -1, huge_size);
	if (save2 < 0)
		return EXIT_FAILURE;

	if (set_node_huge(node1, save1 + 4, huge_size) < 0)
		return EXIT_FAILURE;

	if (set_node_huge(node2, save2 + 4, huge_size) < 0)
		return EXIT_FAILURE;

	length = 4 * huge_size * 1024;
	if (mmap_bind_node_huge(node1, length))
		return EXIT_FAILURE;

	if (mmap_bind_node_huge(node2, length))
		return EXIT_FAILURE;

	length = 2 * huge_size * 1024;

	switch(pid = fork()) {
	case 0:
		exit(loop_move_pages(node1, node2, length));
	case -1:
		perror("- fail: fork");

		return EXIT_FAILURE;
	default:
		break;
	}
	if (mmap_offline_node_huge(length))
		code = EXIT_FAILURE;
	if (kill(pid, SIGKILL)) {
		perror("kill");
		code = EXIT_FAILURE;
	}
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		code = EXIT_FAILURE;
	}
	if (WIFEXITED(status))
		code = EXIT_FAILURE;
	if (set_node_huge(node1, save1, huge_size) < 0)
		code = EXIT_FAILURE;
	if (set_node_huge(node2, save2, huge_size) < 0)
		code = EXIT_FAILURE;

	return code;
}

/* Migrate KSM pages repetitively. */
static int migrate_ksm()
{
	int node1, node2, i, j, m;
	int pagesz = getpagesize();
	long run;
	void *pages[NR_PAGE];
	unsigned long mask1[NR_NODE] = { 0 };
	unsigned long mask2[NR_NODE] = { 0 };

	print_start(__func__);
	if (get_numa(&node1, &node2))
		return EXIT_FAILURE;

	for (i = 0; i < NR_PAGE; i++)
	{
		pages[i] = safe_mmap(NULL, pagesz, PROT_READ | PROT_WRITE |
				     PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
				     -1, 0);
		if (!pages[i])
			goto out;

		if (madvise(pages[i], pagesz, MADV_MERGEABLE) < 0) {
			perror("madvise");
			goto out;
		}
		mask1[0] = 1 << node1;
		if (safe_mbind(pages[i], pagesz, MPOL_BIND, mask1, NR_NODE, 0))
			goto out;

		memset(pages[i], 0, pagesz);
	}
	run = scan_ksm();
	if (run < 0)
		goto out;

	printf("- info: call migrate_pages() repetitively.\n");
	for (m = 0; m < NR_LOOP; m++) {
		int n = m % 2;

		if (n) {
			mask1[0] = 1 << node2;
			mask2[0] = 1 << node1;
		} else {
			mask1[0] = 1 << node1;
			mask2[0] = 1 << node2;
		}
		if (safe_migrate_pages(0, NR_NODE, mask1, mask2))
			goto out;
	}
	for (i = 0; i < NR_PAGE; i++)
		safe_munmap(pages[i], pagesz);

	if (run == 1)
		goto pass;

	/* Restore. */
	if (write_value("/sys/kernel/mm/ksm/run", run))
		return EXIT_FAILURE;
pass:
	printf("- pass: %s\n", __func__);

	return EXIT_SUCCESS;
out:
	for (j = 0; j < i; j++)
		safe_munmap(pages[j], pagesz);

	return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	size_t free_size;
	long bug = 0;
	long select;
	long code = 0;

	if (argc != 1)
		select = atol(argv[1]);
	free_size = get_meminfo("MemFree:");
	if (free_size < 0)
		return EXIT_FAILURE;

	if (argc == 1 || select == ++bug) {
		/* Allocate a bit more to trigger swapping/OOM. */
		code += alloc_mmap(free_size * 1.2);
		code += hotplug_memory();
		if (argc != 1)
			return code;
	}
	if (argc == 1 || select == ++bug) {
		code += migrate_huge_offline(free_size);
		code += hotplug_memory();
		if (argc != 1)
			return code;
	}
	if (argc == 1 || select == ++bug) {
		code += migrate_ksm();
		if (argc != 1)
			return code;
	}
	return code;
}
