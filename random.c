// SPDX-License-Identifier: GPL-2.0-only
/*
 * random kernel bug collection
 */
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#define MADV_SOFT_OFFLINE 101
#define MPOL_BIND 2
#define MPOL_MF_MOVE_ALL (1 << 2)
#define NR_BUG 5000
#define NR_LOOP 1000
#define NR_NODE 4096
#define NR_PAGE 20
#define NR_THREAD 10

struct bug {
	int number;
	int (* func)(void *data);
	void *data;
	char *string;
};

static int alloc_mmap(size_t length);
static int alloc_mmap_hotplug_memory(void *data);
static struct bug *new(int number, int (* func)(void *data), void *data,
		       char *string);
static int build_kernel();
static int cap_cpu();
static int cat(const char *from, FILE *fp_to);
static int copy(const char *from, const char *to);
static void delete(struct bug *bug);
static int fill_semget(void *data);
static size_t get_meminfo(const char *field);
static int get_numa(int *node1, int *node2);
static int hotplug_cpu(void *data);
static int hotplug_memory();
static void list_bug(struct bug *bugs[]);
static void loop_mmap(size_t length);
static int loop_move_pages(int node1, int node2, size_t length);
static int migrate_huge_hotplug_memory(void *data);
static int migrate_huge_offline(size_t free_size);
static int migrate_ksm(void *data);
static int mmap_bind_node_huge(int node, size_t length);
static int mmap_hugetlbfs(void *data);
static int mmap_offline_node_huge(size_t length);
static int oom(void *data);
static void print_start(const char *name);
static int range(char *string, bool *array, int size, bool value);
static int read_all(const char *path);
static int read_file(const char *path, char *buf, size_t size);
static int read_tree(void *data);
static long read_value(const char *path);
static int runc(void *data);
static int run_fuzzer();
static int run_kvm(const char *devid);
static int safe_chdir(const char *path);
static FILE *safe_fdopen(int fd, const char *mode);
static pid_t safe_fork();
static int safe_ferror(FILE *fp, const char *reason);
static FILE *safe_fopen(const char *path, const char *mode);
static int safe_lstat(const char *path, struct stat *stat);
static void *safe_malloc(size_t length);
static long safe_mbind(void *addr, unsigned long length, int mode,
		       const unsigned long *nodemask, unsigned long maxnode,
		       unsigned flags);
static int safe_mkdir(const char* path, mode_t mode);
static void *safe_mmap(void *addr, size_t length, int prot, int flags, int fd,
		       off_t offset);
static int safe_munmap(void *addr, size_t length);
static int safe_mlock(const void *addr, size_t length);
static long safe_migrate_pages(int pid, unsigned long max_node,
			       const unsigned long *old_nodes,
			       const unsigned long *new_nodes);
static DIR *safe_opendir(const char *path);
static int safe_open(const char *path, int flags);
static int safe_unlink(const char *path);
static int safe_waitpid(pid_t pid, int *status, int options);
static int scan_ksm();
static long set_node_huge(int node, long size, size_t huge_size);
static void *thread_mmap(void *data);
static void usage(const char *name);
static int write_file(const char *path, char *buf, size_t size);
static int write_value(const char *path, long value);

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

static DIR *safe_opendir(const char *path)
{
	DIR *dir = opendir(path);

	if (!dir)
		fprintf(stderr, "opendir %s: %s\n", path, strerror(errno));

	return dir;
}

static FILE *safe_fopen(const char *path, const char *mode)
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
	int code = munmap(addr, length);

	if (code)
		fprintf(stderr, "munmap %zu: %s\n", length, strerror(errno));

	return code;
}

static long safe_mbind(void *addr, unsigned long length, int mode,
		       const unsigned long *nodemask, unsigned long maxnode,
		       unsigned flags)
{
	long code = syscall(__NR_mbind, (long)addr, length, mode,
			    (long)nodemask, maxnode, flags);

	if (code)
		perror("mbind");

	return code;
}

static int safe_mlock(const void *addr, size_t length)
{
	int code = mlock(addr, length);

	if (code)
		fprintf(stderr, "munmap %zu: %s\n", length, strerror(errno));

	return code;
}

static long safe_migrate_pages(int pid, unsigned long max_node,
			       const unsigned long *old_nodes,
			       const unsigned long *new_nodes)
{
	long code = syscall(__NR_migrate_pages, pid, max_node, old_nodes,
			    new_nodes);

	if (code < 0)
		perror("migrate_pages");

	return code;
}

static int safe_ferror(FILE *fp, const char *reason)
{
	int code = ferror(fp);

	if (code) {
		perror(reason);
		fclose(fp);
	}
	return code;
}

static int safe_lstat(const char *path, struct stat *stat)
{
	int code = lstat(path, stat);

	if (code)
		fprintf(stderr, "lstat %s: %s\n", path, strerror(errno));

	return code;
}

static int safe_open(const char *path, int flags)
{
	int fd = open(path, flags);

	if (fd < 0)
		fprintf(stderr, "open %s: %s\n", path, strerror(errno));

	return fd;
}

static FILE *safe_fdopen(int fd, const char *mode)
{
	FILE *fp = fdopen(fd, mode);

	if (!fp) {
		perror("fdopen");
		close(fd);
	}
	return fp;
}

static struct bug *new(int number, int (* func)(void *data), void *data,
		       char *string)
{
	struct bug *bug = safe_malloc(sizeof(struct bug));

	if (!bug)
		exit(EXIT_FAILURE);

	bug->number = number;
	bug->func = func;
	bug->data = data;
	bug->string = string;

	return bug;
}

static void delete(struct bug *bug)
{
	free(bug);
}

static size_t get_meminfo(const char *field)
{
	FILE *fp = safe_fopen("/proc/meminfo", "r");
	char *line = NULL;
	char key[1024];
	size_t length = 0;
	size_t value = -1;

	if (!fp)
		return -1;

	while (getline(&line, &length, fp) != -1) {
		sscanf(line, "%s%zu%*s", key, &value);
		if (!strcmp(field, key))
			goto out;
	}
	fprintf(stderr, "- error getting %s in meminfo.\n", field);
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

	fread(value, sizeof(value), 1, fp);
	if (safe_ferror(fp, "read nr_hugepages"))
		return -1;

	save = atol(value);
	if (size < 0)
		goto out;

	snprintf(value, sizeof(value), "%ld", size);
	fwrite(value, sizeof(value), 1, fp);
	fflush(fp);
	if (safe_ferror(fp, "write nr_hugepages"))
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
				return 1;
			}
			usleep(1000);
			continue;
		}
		memset(addr, 0, length);

		code = madvise(addr, length, MADV_SOFT_OFFLINE);
		if(safe_munmap(addr, length))
			return 1;

		/* madvise() could return >= 0 on success. */
		if (code < 0 && errno != EBUSY) {
			perror("madvise");
			return 1;
		}
	}
	printf("- pass: %s\n", __func__);
	return 0;
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
	if (addr == MAP_FAILED || munmap(addr, length))
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

	return 1;
}

static int mmap_bind_node_huge(int node, size_t length)
{
	void *addr;
	unsigned long mask[NR_NODE] = { 0 };

	printf("- mmap and free %zu bytes hugepages on node %d\n",
	       length, node);
	addr = safe_mmap(NULL, length, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	if (addr == MAP_FAILED)
		return 1;

	mask[0] = 1 << node;
	if (safe_mbind(addr, length, MPOL_BIND, mask, NR_NODE, 0) ||
	    safe_mlock(addr, length) || safe_munmap(addr, length))
		return 1;

	return 0;
}

static int get_numa(int *node1, int *node2)
{
	char *line = NULL;
	size_t length = 0;
	FILE *fp;

	fp = safe_fopen("/sys/devices/system/node/has_memory", "r");
	if (!fp) {
		fprintf(stderr, "- error requiring NUMA nodes.\n");
		return 1;
	}
	*node1 = -1;
	*node2 = -1;
	getline(&line, &length, fp);
	sscanf(line, "%d%*c%d", node1, node2);
	free(line);
	fclose(fp);

	if (*node1 == -1 || *node2 == -1) {
		fprintf(stderr, "- error requiring 2 NUMA nodes.\n");
		return 1;
	}
	printf("- use NUMA nodes %d,%d.\n", *node1, *node2);
	return 0;
}

static int read_file(const char *path, char *buf, size_t size)
{
	int fd = safe_open(path, O_RDONLY | O_NONBLOCK);
	FILE *fp;

	if (fd < 0)
		return 1;

	fp = safe_fdopen(fd, "r");
	if (!fp)
		return 1;

	fread(buf, size, 1, fp);
	if (safe_ferror(fp, path)) {
		close(fd);
		return 1;
	}
	fclose(fp);
	close(fd);

	return 0;
}

static long read_value(const char *path)
{
	char value[1024];

	if (read_file(path, value, sizeof(value)))
		return -1;

	return atol(value);
}

static int write_file(const char *path, char *buf, size_t size)
{
	FILE *fp = safe_fopen(path, "w");

	if (!fp)
		return -1;

	assert(buf);
	fwrite(buf, size, 1, fp);
	fflush(fp);
	if (safe_ferror(fp, __func__))
		return 1;

	fclose(fp);
	return 0;
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

	fread(value, sizeof(value), 1, fp);
	if (safe_ferror(fp, "read ksm"))
		return -1;

	run = atoi(value);
	if (run != 1) {
		fwrite("1", 2, 1, fp);
		fflush(fp);
		if (safe_ferror(fp, "write ksm"))
			return -1;
	}
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
	printf("- KSM takes %ds to run two full scans.\n", count);
	return run;
out:
	snprintf(value, sizeof(value), "%d", run);
	fwrite(value, sizeof(value), 1, fp);
	fflush(fp);
	if (!safe_ferror(fp, "restore ksm"))
		fclose(fp);

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

	if (!length)
		size = 2UL * 1024 * 1024 * 1024 / NR_THREAD;

	for (i = 0; i < NR_THREAD; i++) {
		if (length)
			printf("- mmap %d%% memory: %zu\n",
			       100 / NR_THREAD, size);
		else
			printf("- mmap memory: %zu\n", size);

		if (pthread_create(&thread[i], NULL, thread_mmap,
				   (void *)size))
			perror("pthread_create");

		/* Reset until OOM. */
		if (!length)
			i = 0;
	}
	for (i = 0; i < NR_THREAD; i++)
		pthread_join(thread[i], NULL);

	free(thread);
}

static pid_t safe_fork()
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
		perror("fork");

	return pid;
}

/* Allocate memory and mmap them. */
static int alloc_mmap(size_t length)
{
	pid_t pid;

	if (length)
		print_start(__func__);

	pid = safe_fork();
	switch(pid) {
	case -1:
		return 1;
	case 0:
		loop_mmap(length * 1024);
		exit(EXIT_SUCCESS);
	default:
		break;
	}
	if (safe_waitpid(pid, NULL, 0) < 0)
		return 1;

	return 0;
}

/* Offline and online all memory. */
static int hotplug_memory()
{
	char *base = "/sys/devices/system/memory";
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *memory;
	FILE *fp;
	int value;

	print_start(__func__);
	dir = safe_opendir(base);
	if (!dir)
		return 1;

	while ((memory = readdir(dir))) {
		if (!strcmp(memory->d_name, ".") ||
		    !strcmp(memory->d_name, "..") ||
		    memory->d_type != DT_DIR ||
		    strncmp(memory->d_name, "memory", 6))
			continue;

		snprintf(path, sizeof(path), "%s/%s/online", base,
			 memory->d_name);
		value = read_value(path);
		if (value < 0)
			goto out;

		if (!value)
			continue;

		fp = fopen(path, "w");
		if (!fp)
			goto out;

		fwrite("0", 2, 1, fp);
		fflush(fp);
		if (safe_ferror(fp, "offline"))
			continue;

		fwrite("1", 2, 1, fp);
		fflush(fp);
		if (safe_ferror(fp, "online"))
			goto out;

		fclose(fp);
	}
	closedir(dir);
	printf("- pass: %s\n", __func__);
	return 0;
out:
	closedir(dir);
	return 1;
}

/* Migrate hugepages while soft offlining. */
static int migrate_huge_offline(size_t free_size)
{
	size_t huge_size, length;
	int node1, node2, status;
	int code = 0;
	long save1, save2;
	pid_t pid;

	print_start(__func__);
	if (get_numa(&node1, &node2))
		return 1;

	huge_size = get_meminfo("Hugepagesize:");
	if (huge_size < 0)
		return 1;

	/* 4 pages are required to trigger the bug. */
	if (8 * huge_size > free_size) {
		fprintf(stderr,
			"- error allocating memory for 8 hugepages.\n");
		return 1;
	}
	save1 = set_node_huge(node1, -1, huge_size);
	if (save1 < 0)
		return 1;

	save2 = set_node_huge(node2, -1, huge_size);
	if (save2 < 0)
		return 1;

	if (set_node_huge(node1, save1 + 4, huge_size) < 0 ||
	    set_node_huge(node2, save2 + 4, huge_size) < 0)
		return 1;

	length = 4 * huge_size * 1024;
	if (mmap_bind_node_huge(node1, length) ||
	    mmap_bind_node_huge(node2, length))
		return 1;

	length = 2 * huge_size * 1024;
	pid = safe_fork();
	switch(pid) {
	case -1:
		return 1;
	case 0:
		exit(loop_move_pages(node1, node2, length));
	default:
		break;
	}
	if (mmap_offline_node_huge(length))
		code = 1;
	if (kill(pid, SIGKILL)) {
		perror("kill");
		code = 1;
	}
	if (safe_waitpid(pid, &status, 0) < 0)
		code = 1;

	if (WIFEXITED(status) || set_node_huge(node1, save1, huge_size) < 0 ||
	    set_node_huge(node2, save2, huge_size) < 0)
		code = 1;

	return code;
}

/* Migrate KSM pages repetitively. */
static int migrate_ksm(void *data)
{
	int node1, node2, i, j, m;
	int pagesz = getpagesize();
	long run;
	void *pages[NR_PAGE];
	unsigned long mask1[NR_NODE] = { 0 };
	unsigned long mask2[NR_NODE] = { 0 };

	print_start(__func__);
	if (get_numa(&node1, &node2))
		return 1;

	for (i = 0; i < NR_PAGE; i++) {
		pages[i] = safe_mmap(NULL, pagesz, PROT_READ | PROT_WRITE |
				     PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
				     -1, 0);
		if (pages[i] == MAP_FAILED)
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

	printf("- call migrate_pages() repetitively.\n");
	for (m = 0; m < NR_LOOP; m++) {
		int n = m % 2;

		if (n) {
			mask1[0] = 1 << node2;
			mask2[0] = 1 << node1;
		} else {
			mask1[0] = 1 << node1;
			mask2[0] = 1 << node2;
		}
		if (safe_migrate_pages(0, NR_NODE, mask1, mask2) < 0)
			goto out;
	}
	for (i = 0; i < NR_PAGE; i++)
		if (safe_munmap(pages[i], pagesz))
			return 1;

	if (run == 1)
		goto pass;

	/* Restore. */
	if (write_value("/sys/kernel/mm/ksm/run", run))
		return 1;
pass:
	printf("- pass: %s\n", __func__);
	return 0;
out:
	for (j = 0; j < i; j++)
		safe_munmap(pages[j], pagesz);

	return 1;
}

static int read_all(const char *path)
{
	DIR *dir = safe_opendir(path);
	struct dirent *entry;
	struct stat dent_st;
	char subpath[PATH_MAX];
	char buf[1024];
	static unsigned long count = 0;

	if (!(count++ % 10))
		printf("- %s\n", path);
	if (!dir)
		return 1;

	while ((entry = readdir(dir))) {
		if (!strcmp(entry->d_name, ".") ||
		    !strcmp(entry->d_name, ".."))
			continue;

		snprintf(subpath, sizeof(subpath), "%s/%s", path,
			 entry->d_name);

		switch(entry->d_type) {
		case DT_DIR:
			read_all(subpath);
			break;
		case DT_LNK:
			continue;
		case DT_UNKNOWN:
			if (safe_lstat(subpath, &dent_st)) {
				closedir(dir);
				return 1;
			}
			switch(dent_st.st_mode & S_IFMT) {
			case S_IFDIR:
				read_all(subpath);
				break;
			case S_IFLNK:
				continue;
			default:
				read_file(subpath, buf, sizeof(buf));
			}
			break;
		default:
			read_file(subpath, buf, sizeof(buf));
		}
	}
	closedir(dir);
	return 0;
}

static int alloc_mmap_hotplug_memory(void *data)
{
	int code = alloc_mmap((size_t)data);

	if (!code)
		code = hotplug_memory();

	return code;
}

static int migrate_huge_hotplug_memory(void *data)
{
	int code = migrate_huge_offline((size_t)data);

	if (!code)
		code = hotplug_memory();

	return code;
}

static int read_tree(void *data)
{
	const char *path = (const char *)data;
	int code;
	char string[100];

	snprintf(string, sizeof(string), "%s %s", __func__, path);
	print_start(string);
	code = read_all(path);
	if (!code)
		printf("- pass: %s\n", string);

	return code;
}

static void list_bug(struct bug *bugs[])
{
	int i;

	for (i = 0; bugs[i]; i++)
		printf("%d: %s\n", bugs[i]->number, bugs[i]->string);
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s %s\n%s\n", name,
		"[-l] [-b] [-k<#devid>] [-x #bug] [#bug]",
"-b: build kernel from linux-next.\n"
"-f: run a syscall fuzzer at the end.\n"
"-h: print out this text.\n"
"-k: run KVM with optional #devid passthrough after bugs.\n"
"-l: list all bugs numbers and their descriptions.\n"
"-x: exclude bugs by numbers.\n"
"#bug: Trigger bugs by numbers.\n"
"#bug can be specified multiple times and used as a range, e.g., 0-3");
}

static int cat(const char *from, FILE *fp_to)
{
	FILE *fp = safe_fopen(from, "r");
	int c;

	if (!fp)
		return 1;

	while ((c = getc(fp)) != EOF)
		putc(c, fp_to);

	fclose(fp);
	return 0;
}

static int copy(const char *from, const char *to)
{
	FILE *fp = safe_fopen(to, "w");

	if (!fp || cat(from, fp))
		return 1;

	fclose(fp);
	return 0;
}

/* Offline and online all CPUs. */
static int hotplug_cpu(void *data)
{
	char *base = "/sys/devices/system/cpu";
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *cpu;
	int total = 1, value;
	FILE *fp;

	if (data)
		print_start(__func__);

	dir = safe_opendir(base);
	if (!dir)
		return 1;

	while ((cpu = readdir(dir))) {
		/* CPU0 offline is not always possible. */
		if (!strcmp(cpu->d_name, ".") ||
		    !strcmp(cpu->d_name, "..") ||
		    cpu->d_type != DT_DIR ||
		    strncmp(cpu->d_name, "cpu", 3) ||
		    !isdigit(cpu->d_name[3]) ||
		    !strcmp(cpu->d_name, "cpu0"))
			continue;

		snprintf(path, sizeof(path), "%s/%s/online", base,
			 cpu->d_name);
		value = read_value(path);
		if (value < 0)
			goto out;

		if (!value)
			continue;

		total++;
		if (!data)
			continue;

		fp = fopen(path, "w");
		fwrite("0", 2, 1, fp);
		fflush(fp);
		if (safe_ferror(fp, "offline"))
			goto out;

		fwrite("1", 2, 1, fp);
		fflush(fp);
		if (safe_ferror(fp, "online"))
			goto out;

		fclose(fp);
	}
	closedir(dir);
	if (!data)
		return total;

	printf("- pass: %s\n", __func__);
	return 0;
out:
	closedir(dir);
	return 1;
}

static int build_kernel()
{
	DIR *dir;
	struct utsname uts;
	char cmd[1024], *prefix;
	char *diff = "/tmp/test.patch";
	int cpu = cap_cpu();

	if (cpu < 1)
		return 1;

	if (system("rpm -q ncurses-devel") &&
	    system("dnf -y install openssl-devel bc bison flex patch "
		   "ncurses-devel elfutils-libelf-devel qemu-kvm genisoimage "
		   "runc glibc-static"))
			return 1;

	dir = opendir("./linux-next");
	if (!dir && system("git clone https://git.kernel.org/pub/scm/linux/"
			   "kernel/git/next/linux-next.git"))
			return 1;

	if (dir)
		closedir(dir);

	if (safe_chdir("./linux-next"))
		return 1;

	if(access(".config", F_OK)) {
		if (uname(&uts)) {
			perror("uname");
			return 1;
		}
		if (!strcmp(uts.machine, "x86_64")) {
			prefix="x86";
		} else if (!strcmp(uts.machine, "aarch64")) {
			prefix="arm64";
		} else if (!strcmp(uts.machine, "ppc64le")) {
			prefix="powerpc";
		} else if (!strcmp(uts.machine, "s390x")) {
			prefix="s390";
		} else {
			fprintf(stderr, "- error supporting arch %s.\n",
				uts.machine);
			return 1;
		}
		snprintf(cmd, sizeof(cmd), "../%s.config", prefix);
		if (copy(cmd, "./.config"))
			return 1;
	} else {
		if (system("git remote update"))
			return 1;
	}
	snprintf(cmd, sizeof(cmd), "git diff > %s", diff);
	if (system(cmd))
		return 1;

	if (system("git reset --hard origin/master"))
		return 1;

	if (!access(diff, F_OK)) {
		snprintf(cmd, sizeof(cmd), "patch -Np1 < %s", diff);
		if (system(cmd))
			return 1;
	}
	if (!access("./warn.txt", F_OK)) {
		if (copy("./warn.txt", "./warn.txt.orig"))
			return 1;
	}
	snprintf(cmd, sizeof(cmd), "make -j %d 2> warn.txt", cpu);
	if (system(cmd) || system("make modules_install") ||
	    system("make install"))
		return 1;

	if (!access("./warn.txt", F_OK) && cat("./warn.txt", stdout))
			return 1;

	return 0;
}

static int range(char *string, bool *array, int size, bool value)
{
	int i, j, len, start, end;
	char buf[100];

	assert(string);
	assert(array);
	len = strlen(string);

	for (i = 0; i < len; i++) {
		if (!isdigit(string[i]))
			break;
	}
	if (!i)
		goto out;

	if (i == len) {
		i = atoi(string);
		if (i >= size)
			goto out;

		array[i] = value;
		return 0;
	}
	if (string[i] != '-')
		goto out;

	for (j = i + 1; j < len; j++) {
		if (!isdigit(string[j]))
			break;
	}
	if (!j || j != len)
		goto out;

	snprintf(buf, i + 1, string);
	start = atoi(buf);
	end = atoi(string + i + 1);
	if (start >= end || start >= size)
		goto out;

	for (; start <= end; start++)
		array[start] = value;

	return 0;
out:
	fprintf(stderr, "- error parsing #bug or format.\n");
	return 1;
}

static int oom(void *data)
{
	int node1, node2;
	unsigned long mask[NR_NODE] = { 0 };
	char string[100];
	const char *prefix = "normal";

	if (data)
		prefix = "NUMA";

	snprintf(string, sizeof(string), "%s %s", prefix, __func__);
	print_start(string);
	if (data) {
		if (get_numa(&node1, &node2))
			return 1;

		mask[0] = 1 << node2;
		if (syscall(__NR_set_mempolicy, MPOL_BIND, mask, NR_NODE)) {
			perror("set_mempolicy");
			return 1;
		}
	}
	alloc_mmap(0);
	printf("- pass: %s\n", string);

	return 0;
}

static int run_kvm(const char *devid)
{
	const char *distro = "ubuntu-20.04-server-cloudimg";
	const char *bios = "";
	const char *vfio = "/sys/bus/pci/drivers/vfio-pci";
	const char *prefix;
	struct utsname uts;
	char buf[1024], name[1024];
	char qcow2[100], image[100], iso[100], vendor[100], device[100];
	char sysfs[100];
	char sriov[100] = "";
	char driver[PATH_MAX];
	ssize_t size = 0;

	if (uname(&uts)) {
		perror("uname");
		return 1;
	}
	if (!strcmp(uts.machine, "x86_64")) {
		prefix = "amd64";
	} else if (!strcmp(uts.machine, "aarch64")) {
		prefix = "arm64";
		bios = "-bios /usr/share/AAVMF/AAVMF_CODE.fd "
		       "-M gic-version=host";
	} else if (!strcmp(uts.machine, "ppc64le")) {
		prefix = "ppc64el";
	} else {
		prefix = uts.machine;
	}
	snprintf(image, sizeof(image), "./%s-%s.img", distro, prefix);
	snprintf(qcow2, sizeof(buf), "./%s.qcow2", distro);
	prefix = "https://cloud-images.ubuntu.com/releases/focal/release/";
	if (access(qcow2, F_OK)) {
		if (access(image, F_OK)) {
			snprintf(buf, sizeof(buf), "curl -O %s/%s", prefix,
				 image);
			if (system(buf))
				return 1;
		}
		snprintf(buf, sizeof(buf),
			 "qemu-img create -b %s -f qcow2 %s 1T", image, qcow2);
		if (system(buf))
			return 1;
	}
	snprintf(iso, sizeof(iso), "./%s.iso", distro);
	if (access(iso, F_OK)) {
		snprintf(buf, sizeof(buf), "instance-id: %s\n"
			 "local-hostname: %s\n", distro, distro);
		if (write_file("./meta-data", buf, strlen(buf)))
			return 1;

		snprintf(buf, sizeof(buf), "#cloud-config\npassword: %s\n"
			 "chpasswd: { expire: False }\nssh_pwauth: True\n",
			 distro);
		if (write_file("./user-data", buf, strlen(buf)))
			return 1;

		snprintf(buf, sizeof(buf), "genisoimage -output %s "
			 "-volid cidata -joliet -rock user-data meta-data",
			 iso);
		if (system(buf))
			return 1;
	}
	snprintf(sysfs, sizeof(sysfs), "/sys/bus/pci/devices/%s", devid);
	snprintf(name, sizeof(name), "%s/reset", sysfs);
	if (devid && !access(name, F_OK)) {
		if (system("modprobe vfio-pci"))
			return 1;

		/* Save the driver name to restore later if possible. */
		snprintf(name, sizeof(name), "%s/driver", sysfs);
		/* It is possible the device has no driver to begin with. */
		if (!access(name, F_OK)) {
			size = readlink(name, driver, sizeof(driver));
			if (size < 0) {
				perror("readlink");
				return 1;
			}
		}
		snprintf(name, sizeof(name), "%s/vendor", sysfs);
		if (read_file(name, vendor, sizeof(vendor)))
			return 1;

		snprintf(name, sizeof(name), "%s/device", sysfs);
		if (read_file(name, device, sizeof(device)))
			return 1;

		/* Have to remove the leading "0x" first. */
		snprintf(buf, sizeof(buf), "%s %s", vendor + 2, device + 2);
		snprintf(name, sizeof(name), "%s/new_id", vfio);
		/* Write to the "new_id" will flip the driver to vfio-pci. */
		if (write_file(name, buf, strlen(buf)))
			return 1;

		snprintf(name, sizeof(name), "%s/driver/unbind", sysfs);
		if (write_file(name, (char *)devid, strlen(devid)))
			return 1;

		snprintf(name, sizeof(name), "%s/bind", vfio);
		if (write_file(name, (char *)devid, strlen(devid)))
			return 1;

		snprintf(sriov, sizeof(sriov), "-device vfio-pci,host=%s",
			 devid);
	}
	snprintf(buf, sizeof(buf), "/usr/libexec/qemu-kvm -name %s -cpu host "
		 "-smp 2 -m 2g -hda %s -cdrom %s %s "
		 "-nic user,hostfwd=tcp::2222-:22 -nographic %s", distro,
		 qcow2, iso, bios, sriov);
	printf("- %s\n", buf);
	if (system(buf))
		return 1;

	if (strlen(sriov)) {
		snprintf(buf, sizeof(buf), "%s %s", vendor + 2, device + 2);
		snprintf(name, sizeof(name), "%s/remove_id", vfio);
		if (write_file(name, buf, strlen(buf)))
			return 1;

		snprintf(name, sizeof(name), "%s/unbind", vfio);
		if (write_file(name, (char *)devid, strlen(devid)))
			return 1;
		/*
		 * To restore,
		 * # echo "$devid" > "/sys/bus/pci/drivers/$driver/bind"
		 * # echo 0 > /sys/class/net/<ifname>/device/sriov_numvfs
		 */
		if (size)
			printf("- driver is %.*s\n.", (int)size, driver);
	}
	return 0;
}

static int run_fuzzer()
{
	int status;
	int cpu = cap_cpu();
	char cmd[100];
	pid_t pid;

	if (cpu < 0)
		return 1;

	if (access("/usr/bin/trinity", F_OK)) {
		if (system("git clone "
			   "https://github.com/kernelslacker/trinity.git"))
			return 1;

		if (safe_chdir("./trinity"))
			return 1;

		if (system("./configure"))
			return 1;

		snprintf(cmd, sizeof(cmd), "make -j %d", cpu);
		if (system(cmd) || system("make install"))
			return 1;
	}
	/* Switch to the user ID #1000. */
	pid = safe_fork();
	switch (pid) {
	case -1:
		return 1;
	case 0:
		if (setuid(1000)) {
			perror("setuid");
			exit(EXIT_FAILURE);
		}
		if (safe_chdir("/tmp"))
			exit(EXIT_FAILURE);

		snprintf(cmd, sizeof(cmd), "trinity -C %d --arch 64", cpu);
		exit(system(cmd));
	default:
		break;
	}
	if (safe_waitpid(pid, &status, 0) < 0)
		return 1;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return 1;
}

static int safe_chdir(const char *path)
{
	if (chdir(path)) {
		perror("chdir");
		return 1;
	}
	return 0;
}

static pid_t safe_waitpid(pid_t pid, int *status, int options)
{
	pid_t code = waitpid(pid, status, options);

	if (code < 0)
		perror("waitpid");

	return code;
}

static int cap_cpu()
{
	int cpu = hotplug_cpu(NULL);

	/*
	 * There is no guarantee a higher thread number will be faster for
	 * parallel compilations.
	 */
	if (cpu > 64)
		cpu = 64;

	return cpu;
}

static int fill_semget(void *data)
{
	int *semid_arr;
	int semid, i, max;
	int total = 0;
	int code = 0;
	FILE *fp = safe_fopen("/proc/sys/kernel/sem", "r");

	print_start(__func__);
	if (!fp)
		return 1;

	if (fscanf(fp, "%*d %*d %*d %d", &max) != 1) {
		fprintf(stderr, "- error getting SEMMNI.");
		fclose(fp);
		return 1;
	}
	semid_arr = safe_malloc(sizeof(int) * (max + 1));
	if (!semid_arr)
		return 1;

	while ((semid = semget(IPC_PRIVATE, 10, IPC_CREAT | IPC_EXCL))
	       != -1) {
		semid_arr[total++] = semid;
		if (total == max + 1) {
			fprintf(stderr, "- error reaching SEMMNI.");
			code = 1;
			goto out;
		}
	}

	if (errno != ENOSPC) {
		fprintf(stderr, "- error not returning ENOSPC.");
		code = 1;
	}
out:
	for (i = 0; i < total; i++) {
		if (semctl(semid_arr[i], 0, IPC_RMID)) {
			perror("semctl IPC_RMID");
			code = 1;
		}
	}
	free(semid_arr);
	if (!code)
		printf("- pass: %s\n", __func__);

	return code;
}

static int mmap_hugetlbfs(void *data)
{
	int fd;
	char *mount = "/dev/hugepages";
	char *nr_huge = "/proc/sys/vm/nr_hugepages";
	char name[100];
	size_t huge_size, curr;
	long save;
	void *addr;

	print_start(__func__);
	snprintf(name, sizeof(name), "%s/mmapfile%d", mount, getpid());
	fd = safe_open(name, O_RDWR | O_CREAT);
	if (fd < 0)
		return 1;

	save = read_value(nr_huge);
	if (save < 0 || write_value(nr_huge, (long)data))
		return 1;

	huge_size = get_meminfo("Hugepagesize:");
	if (huge_size < 0)
		return 1;

	huge_size *= 1024;
	addr = safe_mmap(NULL, huge_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 fd, 0);
	if (addr == MAP_FAILED)
		return 1;

	/* Force to allocate page and change HugePages_Free. */
	*(int *)addr = 0;
	curr = get_meminfo("HugePages_Free:");
	if (curr != (long)data - 1) {
		fprintf(stderr, "- error nr_hugepages is %ld.\n", curr);
		return 1;
	}

	if (safe_munmap(addr, huge_size) || write_value(nr_huge, save))
		return 1;

	close(fd);
	if (safe_unlink(name))
		return 1;

	printf("- pass: %s\n", __func__);
	return 0;
}

static int write_value(const char *path, long value)
{
	char buf[100];

	snprintf(buf, sizeof(buf), "%ld", value);
	return write_file(path, buf, strlen(buf));
}

static int safe_unlink(const char *path)
{
	int code = unlink(path);

	if (code)
		perror("unlink");

	return code;
}

static int runc(void *data)
{
	const char *spec_file = "\
{\n\
	\"ociVersion\": \"1.0.0\",\n\
	\"process\": {\n\
		\"terminal\": false,\n\
		\"user\": {\n\
			\"uid\": 0,\n\
			\"gid\": 0\n\
		},\n\
		\"args\": [\n\
			\"hello\"\n\
		],\n\
		\"env\": [\n\
			\"PATH=/usr/sbin:/usr/bin:/sbin:/bin\",\n\
			\"TERM=xterm\"\n\
		],\n\
		\"cwd\": \"/\",\n\
		\"capabilities\": {\n\
			\"bounding\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"effective\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"inheritable\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"permitted\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			],\n\
			\"ambient\": [\n\
				\"CAP_AUDIT_WRITE\",\n\
				\"CAP_KILL\",\n\
				\"CAP_NET_BIND_SERVICE\"\n\
			]\n\
		},\n\
		\"rlimits\": [\n\
			{\n\
				\"type\": \"RLIMIT_NOFILE\",\n\
				\"hard\": 1024,\n\
				\"soft\": 1024\n\
			}\n\
		],\n\
		\"noNewPrivileges\": true\n\
	},\n\
	\"root\": {\n\
		\"path\": \"rootfs\",\n\
		\"readonly\": true\n\
	},\n\
	\"hostname\": \"runc\",\n\
	\"mounts\": [\n\
		{\n\
			\"destination\": \"/proc\",\n\
			\"type\": \"proc\",\n\
			\"source\": \"proc\"\n\
		},\n\
		{\n\
			\"destination\": \"/dev\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"tmpfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"strictatime\",\n\
				\"mode=755\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/pts\",\n\
			\"type\": \"devpts\",\n\
			\"source\": \"devpts\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"newinstance\",\n\
				\"ptmxmode=0666\",\n\
				\"mode=0620\"\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/shm\",\n\
			\"type\": \"tmpfs\",\n\
			\"source\": \"shm\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"mode=1777\",\n\
				\"size=65536k\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/dev/mqueue\",\n\
			\"type\": \"mqueue\",\n\
			\"source\": \"mqueue\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys\",\n\
			\"type\": \"sysfs\",\n\
			\"source\": \"sysfs\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"ro\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/sys/fs/cgroup\",\n\
			\"type\": \"cgroup\",\n\
			\"source\": \"cgroup\",\n\
			\"options\": [\n\
				\"nosuid\",\n\
				\"noexec\",\n\
				\"nodev\",\n\
				\"relatime\",\n\
				\"ro\"\n\
			]\n\
		},\n\
		{\n\
			\"destination\": \"/usr/bin/hello\",\n\
			\"type\": \"bind\",\n\
			\"source\": \"./hello\",\n\
			\"options\": [\n\
				\"rbind\",\n\
				\"ro\"\n\
			]\n\
		}\n\
	],\n\
	\"linux\": {\n\
		\"resources\": {\n\
		},\n\
		\"namespaces\": [\n\
			{\n\
				\"type\": \"pid\"\n\
			},\n\
			{\n\
				\"type\": \"network\"\n\
			},\n\
			{\n\
				\"type\": \"ipc\"\n\
			},\n\
			{\n\
				\"type\": \"uts\"\n\
			},\n\
			{\n\
				\"type\": \"cgroup\"\n\
			},\n\
			{\n\
				\"type\": \"mount\"\n\
			}\n\
		],\n\
		\"maskedPaths\": [\n\
			\"/proc/kcore\",\n\
			\"/proc/latency_stats\",\n\
			\"/proc/timer_list\",\n\
			\"/proc/timer_stats\",\n\
			\"/proc/sched_debug\",\n\
			\"/sys/firmware\"\n\
		],\n\
		\"readonlyPaths\": [\n\
			\"/proc/asound\",\n\
			\"/proc/bus\",\n\
			\"/proc/fs\",\n\
			\"/proc/irq\",\n\
			\"/proc/sys\",\n\
			\"/proc/sysrq-trigger\"\n\
		]\n\
	}\n\
}\n";
	const char *hello = "\
#include <stdio.h>\n\
\n\
int main()\n\
{\n\
	printf(\"Hello, World!\\n\");\n\
	return 0;\n\
}\n";
	DIR *dir = opendir("./rootfs");

	print_start(__func__);
	if (!dir && safe_mkdir("./rootfs", 0755))
		return 1;

	if (dir)
		closedir(dir);

	if (write_file("./config.json", (char *)spec_file,
		       strlen(spec_file)) ||
	    write_file("./hello.c", (char *)hello, strlen(hello)) ||
	    system("gcc -static -o hello hello.c") || system("runc run root"))
		return 1;

	printf("- pass: %s\n", __func__);

	return 0;
}

int safe_mkdir(const char *path, mode_t mode)
{
	int code = mkdir(path, mode);

	if (code)
		perror("mkdir");

	return code;
}

int main(int argc, char *argv[])
{
	size_t free_size, size;
	int i = 0;
	int j, c;
	int code = 0;
	int xcount = 0;
	struct bug *bugs[NR_BUG] = { NULL };
	char *skip[100] = { NULL };
	const char *devid;
	bool ignore[NR_BUG];
	bool kvm = false;
	bool fuzzer = false;

	free_size = get_meminfo("MemFree:");
	if (free_size < 0)
		return 1;

	size = free_size * 1.2;
	/* Allocate a bit more to trigger swapping/OOM. */
	bugs[i] = new(i, alloc_mmap_hotplug_memory, (void *)size,
		"trigger swapping/OOM, and then offline all memory.");
	i++;
	bugs[i] = new(i, migrate_huge_hotplug_memory, (void *)free_size,
		"migrate hugepages while soft offlining, and then offline "
		"all memory.");
	i++;
	bugs[i] = new(i, migrate_ksm, NULL,
		"migrate KSM pages repetitively.");
	i++;
	bugs[i] = new(i, read_tree, "/sys", "read all sysfs files.");
	i++;
	bugs[i] = new(i, hotplug_cpu, "", "offline and online all CPUs.");
	i++;
	bugs[i] = new(i, oom, NULL, "trigger normal OOM.");
	i++;
	bugs[i] = new(i, oom, "", "trigger NUMA OOM.");
	i++;
	bugs[i] = new(i, read_tree, "/proc", "read all procfs files.");
	i++;
	bugs[i] = new(i, fill_semget, NULL,
		"force semget() to return ENOSPC.");
	i++;
	bugs[i] = new(i, mmap_hugetlbfs, (void *)64,
		"mmap a file in hugetlbfs.");
	i++;
	bugs[i] = new(i, runc, NULL, "spawn a runc container.");
	i++;

	while ((c = getopt(argc, argv, "bhfk::lx:")) != -1) {
		switch(c) {
		case 'b':
			code = build_kernel();
			goto out;
		case 'f':
			fuzzer = true;
			break;
		case 'k':
			kvm = true;
			devid = optarg;
			break;
		case 'l':
			list_bug(bugs);
			goto out;
		case 'x':
			skip[xcount++] = optarg;
			break;
		case 'h': /* fall-through */
		default:
			usage(argv[0]);
			goto out;
		}
	}
	/* These are the arguments after the command-line options. */
	if (optind < argc) {
		if (xcount) {
			fprintf(stderr,
				"- error having both [-x #bug] and [#bug].\n");
			code += 1;
			goto out;
		}
		memset(ignore, true, sizeof(ignore));
		for (; optind < argc; optind++) {
			code = range(argv[optind], ignore, sizeof(ignore),
				     false);
			if (code)
				goto out;
		}
	} else {
		memset(ignore, false, sizeof(ignore));
		for (j = 0; j < xcount; j++) {
			code = range(skip[j], ignore, sizeof(ignore), true);
			if (code)
				goto out;
		}
	}
	for (j = 0; j < i; j++) {
		if (ignore[j])
			continue;

		code += bugs[j]->func(bugs[j]->data);
	}
	if (kvm)
		code += run_kvm(devid);

	if (fuzzer && !code)
		code = run_fuzzer();
out:
	for (j = 0; j < i; j++)
		delete(bugs[j]);

	return code;
}
