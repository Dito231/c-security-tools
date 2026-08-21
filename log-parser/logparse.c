/*
 * logparse.c — Structured log parser for security analysis
 *
 * Reads auth.log / syslog format logs and extracts structured fields:
 * timestamp, hostname, service, PID, message. Supports filtering by
 * pattern and CSV output for pipeline integration.
 *
 * Usage:
 *   ./logparse /var/log/auth.log                       Parse full log
 *   ./logparse -f "Failed password" /var/log/auth.log   Filter by pattern
 *   ./logparse -c /var/log/auth.log                     CSV output
 *   ./logparse -f "sshd" -c /var/log/auth.log           Combined
 *
 * Syslog format expected:
 *   "Mon DD HH:MM:SS hostname service[pid]: message"
 *
 * Author: Gabriel Lopez (@Dito231)
 * License: MIT
 */

#define _GNU_SOURCE  /* for strncasecmp */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>

#define MAX_LINE    4096
#define MAX_FIELD   256

/* Parsed log entry */
typedef struct {
    char timestamp[32];     /* "Mon DD HH:MM:SS" */
    char hostname[MAX_FIELD];
    char service[MAX_FIELD];
    char pid[16];           /* extracted from service[pid] */
    char message[MAX_LINE];
} LogEntry;

/* Statistics counters */
typedef struct {
    unsigned long total_lines;
    unsigned long parsed_lines;
    unsigned long matched_lines;
    unsigned long parse_errors;
} Stats;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <logfile>\n"
        "Options:\n"
        "  -f <pattern>  Filter lines containing pattern (case-insensitive)\n"
        "  -c            Output as CSV\n"
        "  -s            Show summary statistics only\n"
        "  -n <count>    Limit output to first N matching lines\n"
        "  -h            Show this help\n",
        prog);
    exit(EXIT_FAILURE);
}

/*
 * Case-insensitive substring search.
 * Returns pointer to match or NULL.
 */
static const char *strcasestr_custom(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;

    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return NULL;
}

/*
 * Parse a syslog-format line into a LogEntry struct.
 *
 * Expected format:
 *   "Aug 18 14:23:01 myhost sshd[12345]: Failed password for root"
 *    |-- timestamp --| |host| |svc[pid]| |---- message ----|
 *
 * Returns 1 on success, 0 on parse failure.
 */
static int parse_syslog_line(const char *line, LogEntry *entry)
{
    const char *p = line;
    const char *field_start;
    char service_raw[MAX_FIELD];
    char *bracket;

    /* Strip leading whitespace */
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '\0') return 0;

    /* Timestamp: "Mon DD HH:MM:SS" (15 chars for standard syslog) */
    if (strlen(p) < 15) return 0;

    /* Find the third space (end of timestamp) */
    int spaces = 0;
    const char *ts_end = p;
    while (*ts_end && spaces < 3) {
        if (*ts_end == ' ') spaces++;
        ts_end++;
    }
    if (spaces < 3) return 0;
    ts_end--;  /* back up past the space */

    size_t ts_len = (size_t)(ts_end - p);
    if (ts_len >= sizeof(entry->timestamp)) ts_len = sizeof(entry->timestamp) - 1;
    strncpy(entry->timestamp, p, ts_len);
    entry->timestamp[ts_len] = '\0';
    p = ts_end + 1;

    /* Hostname: next token */
    while (*p && isspace((unsigned char)*p)) p++;
    field_start = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (p == field_start) return 0;

    size_t host_len = (size_t)(p - field_start);
    if (host_len >= sizeof(entry->hostname)) host_len = sizeof(entry->hostname) - 1;
    strncpy(entry->hostname, field_start, host_len);
    entry->hostname[host_len] = '\0';

    /* Service[PID]: next token up to ':' */
    while (*p && isspace((unsigned char)*p)) p++;
    field_start = p;
    while (*p && *p != ':') p++;
    if (*p != ':') return 0;

    size_t svc_len = (size_t)(p - field_start);
    if (svc_len >= sizeof(service_raw)) svc_len = sizeof(service_raw) - 1;
    strncpy(service_raw, field_start, svc_len);
    service_raw[svc_len] = '\0';

    /* Split service[pid] */
    bracket = strchr(service_raw, '[');
    if (bracket) {
        *bracket = '\0';
        strncpy(entry->service, service_raw, sizeof(entry->service) - 1);
        entry->service[sizeof(entry->service) - 1] = '\0';

        char *pid_start = bracket + 1;
        char *pid_end = strchr(pid_start, ']');
        if (pid_end) *pid_end = '\0';
        strncpy(entry->pid, pid_start, sizeof(entry->pid) - 1);
        entry->pid[sizeof(entry->pid) - 1] = '\0';
    } else {
        strncpy(entry->service, service_raw, sizeof(entry->service) - 1);
        entry->service[sizeof(entry->service) - 1] = '\0';
        entry->pid[0] = '\0';
    }

    /* Message: everything after ": " */
    p++;  /* skip ':' */
    while (*p && isspace((unsigned char)*p)) p++;
    strncpy(entry->message, p, sizeof(entry->message) - 1);
    entry->message[sizeof(entry->message) - 1] = '\0';

    /* Trim trailing newline */
    size_t msg_len = strlen(entry->message);
    while (msg_len > 0 && (entry->message[msg_len - 1] == '\n' ||
                            entry->message[msg_len - 1] == '\r'))
        entry->message[--msg_len] = '\0';

    return 1;
}

/*
 * Escape a field for CSV output.
 * Wraps in quotes if the field contains commas, quotes, or newlines.
 */
static void print_csv_field(const char *field)
{
    int needs_quotes = 0;
    const char *p;

    for (p = field; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n') {
            needs_quotes = 1;
            break;
        }
    }

    if (needs_quotes) {
        putchar('"');
        for (p = field; *p; p++) {
            if (*p == '"') putchar('"');  /* escape quotes by doubling */
            putchar(*p);
        }
        putchar('"');
    } else {
        fputs(field, stdout);
    }
}

int main(int argc, char *argv[])
{
    FILE *fp;
    char line[MAX_LINE];
    LogEntry entry;
    Stats stats = {0};
    int opt;

    const char *filter = NULL;
    int csv_output = 0;
    int stats_only = 0;
    long max_lines = -1;

    while ((opt = getopt(argc, argv, "f:csn:h")) != -1) {
        switch (opt) {
        case 'f': filter = optarg; break;
        case 'c': csv_output = 1; break;
        case 's': stats_only = 1; break;
        case 'n': max_lines = strtol(optarg, NULL, 10); break;
        case 'h':
        default:  usage(argv[0]);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no input file specified\n");
        usage(argv[0]);
    }

    fp = fopen(argv[optind], "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s': %s\n",
                argv[optind], strerror(errno));
        return EXIT_FAILURE;
    }

    /* CSV header */
    if (csv_output && !stats_only)
        printf("timestamp,hostname,service,pid,message\n");

    while (fgets(line, sizeof(line), fp)) {
        stats.total_lines++;

        if (!parse_syslog_line(line, &entry)) {
            stats.parse_errors++;
            continue;
        }
        stats.parsed_lines++;

        /* Apply filter */
        if (filter) {
            if (!strcasestr_custom(line, filter))
                continue;
        }
        stats.matched_lines++;

        /* Check line limit */
        if (max_lines >= 0 && (long)stats.matched_lines > max_lines)
            break;

        if (stats_only) continue;

        /* Output */
        if (csv_output) {
            print_csv_field(entry.timestamp); putchar(',');
            print_csv_field(entry.hostname);  putchar(',');
            print_csv_field(entry.service);   putchar(',');
            print_csv_field(entry.pid);       putchar(',');
            print_csv_field(entry.message);   putchar('\n');
        } else {
            printf("[%s] %s %s",
                   entry.timestamp, entry.hostname, entry.service);
            if (entry.pid[0])
                printf("[%s]", entry.pid);
            printf(": %s\n", entry.message);
        }
    }

    fclose(fp);

    /* Summary */
    if (stats_only || !csv_output) {
        if (stats_only) printf("\n");
        fprintf(stats_only ? stdout : stderr,
            "--- Summary ---\n"
            "Total lines:   %lu\n"
            "Parsed:        %lu\n"
            "Parse errors:  %lu\n"
            "Matched:       %lu%s\n",
            stats.total_lines,
            stats.parsed_lines,
            stats.parse_errors,
            stats.matched_lines,
            filter ? " (filtered)" : "");
    }

    return EXIT_SUCCESS;
}
