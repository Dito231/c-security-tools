/*
 * procenum.c — Process enumerator via /proc filesystem
 *
 * Lists running processes by reading /proc on Linux. Displays PID,
 * PPID, user, state, memory usage, and command line. Optionally
 * shows open file descriptors for a specific process.
 *
 * Usage:
 *   ./procenum                  List all processes
 *   ./procenum -u root          Filter by user
 *   ./procenum -p 1234          Details for specific PID
 *   ./procenum -f               Include open file descriptors
 *
 * Security relevance:
 *   EDR agents and rootkit detectors enumerate processes through
 *   /proc. Understanding this interface helps you spot discrepancies
 *   between /proc and other enumeration methods (which may indicate
 *   a rootkit hiding processes).
 *
 * Author: Gabriel Lopez (@Dito231)
 * License: MIT
 */

#define _POSIX_C_SOURCE 200809L  /* for readlink */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <getopt.h>
#include <sys/types.h>
#include <errno.h>

#define MAX_PATH    512
#define MAX_LINE    4096
#define MAX_CMDLINE 2048

/* Parsed process info from /proc/[pid]/ */
typedef struct {
    int     pid;
    int     ppid;
    uid_t   uid;
    char    user[64];
    char    name[256];
    char    state;
    long    vm_rss_kb;        /* resident set size in KB */
    long    threads;
    char    cmdline[MAX_CMDLINE];
} ProcInfo;

/* Statistics */
typedef struct {
    int total;
    int displayed;
    int errors;
} Stats;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -u <user>   Filter by username\n"
        "  -p <pid>    Show details for specific PID\n"
        "  -f          Show open file descriptors (with -p)\n"
        "  -t          Sort by resident memory (descending)\n"
        "  -h          Show this help\n",
        prog);
    exit(EXIT_FAILURE);
}

/*
 * Read a file from /proc into a buffer.
 * Returns number of bytes read, or -1 on error.
 */
static int read_proc_file(const char *path, char *buf, size_t bufsize)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    size_t n = fread(buf, 1, bufsize - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return (int)n;
}

/*
 * Parse /proc/[pid]/status for process metadata.
 * Extracts: Name, State, Pid, PPid, Uid, VmRSS, Threads
 */
static int parse_proc_status(int pid, ProcInfo *info)
{
    char path[MAX_PATH];
    char buf[MAX_LINE];
    FILE *fp;

    memset(info, 0, sizeof(*info));
    info->pid = pid;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    fp = fopen(path, "r");
    if (!fp) return -1;

    while (fgets(buf, sizeof(buf), fp)) {
        if (strncmp(buf, "Name:\t", 6) == 0) {
            sscanf(buf + 6, "%255s", info->name);
        } else if (strncmp(buf, "State:\t", 7) == 0) {
            info->state = buf[7];
        } else if (strncmp(buf, "PPid:\t", 6) == 0) {
            info->ppid = atoi(buf + 6);
        } else if (strncmp(buf, "Uid:\t", 5) == 0) {
            info->uid = (uid_t)atoi(buf + 5);
        } else if (strncmp(buf, "VmRSS:", 6) == 0) {
            info->vm_rss_kb = atol(buf + 6);
        } else if (strncmp(buf, "Threads:", 8) == 0) {
            info->threads = atol(buf + 8);
        }
    }
    fclose(fp);

    /* Resolve UID to username */
    struct passwd *pw = getpwuid(info->uid);
    if (pw)
        strncpy(info->user, pw->pw_name, sizeof(info->user) - 1);
    else
        snprintf(info->user, sizeof(info->user), "%d", info->uid);

    return 0;
}

/*
 * Read /proc/[pid]/cmdline.
 * Arguments are separated by null bytes — replace with spaces.
 */
static void read_cmdline(int pid, ProcInfo *info)
{
    char path[MAX_PATH];
    char buf[MAX_CMDLINE];
    int n, i;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    n = read_proc_file(path, buf, sizeof(buf));
    if (n <= 0) {
        snprintf(info->cmdline, sizeof(info->cmdline), "[%s]", info->name);
        return;
    }

    /* Replace null separators with spaces */
    for (i = 0; i < n - 1; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[n] = '\0';

    strncpy(info->cmdline, buf, sizeof(info->cmdline) - 1);
    info->cmdline[sizeof(info->cmdline) - 1] = '\0';
}

/*
 * List open file descriptors for a process by reading /proc/[pid]/fd/.
 * Each entry is a symlink to the actual file/socket/pipe.
 */
static void list_fds(int pid)
{
    char path[MAX_PATH];
    char link_target[MAX_PATH];
    DIR *dir;
    struct dirent *ent;
    ssize_t len;
    int count = 0;

    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    dir = opendir(path);
    if (!dir) {
        printf("  (cannot read fd directory: %s)\n", strerror(errno));
        return;
    }

    printf("  Open file descriptors:\n");
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char fd_path[MAX_PATH * 2];
        snprintf(fd_path, sizeof(fd_path), "%s/%s", path, ent->d_name);
        len = readlink(fd_path, link_target, sizeof(link_target) - 1);
        if (len < 0) continue;
        link_target[len] = '\0';

        printf("    fd %s → %s\n", ent->d_name, link_target);
        count++;
    }
    closedir(dir);
    printf("  Total: %d file descriptors\n", count);
}

/*
 * State character to human-readable description.
 */
static const char *state_desc(char state)
{
    switch (state) {
    case 'R': return "Running";
    case 'S': return "Sleeping";
    case 'D': return "Disk sleep";
    case 'Z': return "Zombie";
    case 'T': return "Stopped";
    case 't': return "Tracing stop";
    case 'X': return "Dead";
    default:  return "Unknown";
    }
}

/* For sorting by memory usage */
static ProcInfo *all_procs = NULL;
static int proc_count = 0;
static int proc_cap = 0;

static int cmp_by_rss(const void *a, const void *b)
{
    const ProcInfo *pa = (const ProcInfo *)a;
    const ProcInfo *pb = (const ProcInfo *)b;
    if (pb->vm_rss_kb > pa->vm_rss_kb) return 1;
    if (pb->vm_rss_kb < pa->vm_rss_kb) return -1;
    return 0;
}

int main(int argc, char *argv[])
{
    DIR *proc_dir;
    struct dirent *ent;
    int opt;

    const char *filter_user = NULL;
    int target_pid = -1;
    int show_fds = 0;
    int sort_by_mem = 0;

    while ((opt = getopt(argc, argv, "u:p:fth")) != -1) {
        switch (opt) {
        case 'u': filter_user = optarg; break;
        case 'p': target_pid = atoi(optarg); break;
        case 'f': show_fds = 1; break;
        case 't': sort_by_mem = 1; break;
        case 'h':
        default:  usage(argv[0]);
        }
    }

    /* Single PID detail mode */
    if (target_pid > 0) {
        ProcInfo info;
        if (parse_proc_status(target_pid, &info) < 0) {
            fprintf(stderr, "Error: cannot read process %d: %s\n",
                    target_pid, strerror(errno));
            return EXIT_FAILURE;
        }
        read_cmdline(target_pid, &info);

        printf("PID:       %d\n", info.pid);
        printf("PPID:      %d\n", info.ppid);
        printf("User:      %s (uid %d)\n", info.user, info.uid);
        printf("Name:      %s\n", info.name);
        printf("State:     %c (%s)\n", info.state, state_desc(info.state));
        printf("Memory:    %ld KB (RSS)\n", info.vm_rss_kb);
        printf("Threads:   %ld\n", info.threads);
        printf("Cmdline:   %s\n", info.cmdline);

        if (show_fds) {
            printf("\n");
            list_fds(target_pid);
        }
        return EXIT_SUCCESS;
    }

    /* Enumerate all processes */
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        fprintf(stderr, "Error: cannot open /proc: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    Stats stats = {0};

    /* Allocate storage if sorting */
    if (sort_by_mem) {
        proc_cap = 256;
        all_procs = malloc(proc_cap * sizeof(ProcInfo));
        if (!all_procs) {
            fprintf(stderr, "Error: out of memory\n");
            return EXIT_FAILURE;
        }
    }

    /* Header */
    if (!sort_by_mem)
        printf("%-8s %-8s %-12s %-2s %8s  %s\n",
               "PID", "PPID", "USER", "ST", "RSS(KB)", "COMMAND");

    while ((ent = readdir(proc_dir)) != NULL) {
        /* Only numeric directory names are PIDs */
        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;

        int pid = atoi(ent->d_name);
        ProcInfo info;

        if (parse_proc_status(pid, &info) < 0) {
            stats.errors++;
            continue;
        }
        read_cmdline(pid, &info);
        stats.total++;

        /* Apply user filter */
        if (filter_user && strcmp(info.user, filter_user) != 0)
            continue;

        stats.displayed++;

        if (sort_by_mem) {
            if (proc_count >= proc_cap) {
                proc_cap *= 2;
                all_procs = realloc(all_procs, proc_cap * sizeof(ProcInfo));
            }
            all_procs[proc_count++] = info;
        } else {
            printf("%-8d %-8d %-12s %-2c %8ld  %s\n",
                   info.pid, info.ppid, info.user, info.state,
                   info.vm_rss_kb, info.cmdline);
        }
    }
    closedir(proc_dir);

    /* Print sorted output */
    if (sort_by_mem && proc_count > 0) {
        qsort(all_procs, proc_count, sizeof(ProcInfo), cmp_by_rss);
        printf("%-8s %-8s %-12s %-2s %8s  %s\n",
               "PID", "PPID", "USER", "ST", "RSS(KB)", "COMMAND");
        for (int i = 0; i < proc_count; i++) {
            printf("%-8d %-8d %-12s %-2c %8ld  %s\n",
                   all_procs[i].pid, all_procs[i].ppid,
                   all_procs[i].user, all_procs[i].state,
                   all_procs[i].vm_rss_kb, all_procs[i].cmdline);
        }
        free(all_procs);
    }

    /* Summary to stderr */
    fprintf(stderr, "\n%d processes enumerated, %d displayed, %d errors\n",
            stats.total, stats.displayed, stats.errors);

    return EXIT_SUCCESS;
}
