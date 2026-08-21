/*
 * hexview.c — Interactive hex dump viewer for binary analysis
 *
 * Displays files in canonical hex+ASCII format with colorized output.
 * Supports offset navigation, byte count limits, and pattern search.
 *
 * Usage:
 *   ./hexview <file>                     Full hex dump
 *   ./hexview -o 0x200 -n 512 <file>     512 bytes from offset 0x200
 *   ./hexview -s "MZ" <file>             Search for byte pattern
 *
 * Author: Gabriel Lopez (@Dito231)
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>

/* ANSI color codes for terminal output */
#define COLOR_RESET   "\033[0m"
#define COLOR_OFFSET  "\033[33m"    /* Yellow — offset column */
#define COLOR_PRINT   "\033[36m"    /* Cyan — printable ASCII bytes */
#define COLOR_NULL    "\033[90m"    /* Gray — null bytes */
#define COLOR_HIGH    "\033[31m"    /* Red — high bytes (>0x7F) */
#define COLOR_MATCH   "\033[42;30m" /* Green bg — search match */

#define BYTES_PER_LINE 16
#define DEFAULT_CHUNK  4096

/* Print usage and exit */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <file>\n"
        "Options:\n"
        "  -o <offset>   Start offset (hex with 0x prefix or decimal)\n"
        "  -n <count>    Number of bytes to display\n"
        "  -s <pattern>  Search for ASCII pattern and highlight matches\n"
        "  -h            Show this help\n",
        prog);
    exit(EXIT_FAILURE);
}

/*
 * Parse an offset value that may be hex (0x...) or decimal.
 * Returns the parsed value or exits on error.
 */
static long parse_offset(const char *str)
{
    char *end;
    long val;

    errno = 0;
    val = strtol(str, &end, 0);  /* base 0 = auto-detect hex/oct/dec */
    if (errno != 0 || *end != '\0' || val < 0) {
        fprintf(stderr, "Invalid offset: %s\n", str);
        exit(EXIT_FAILURE);
    }
    return val;
}

/*
 * Print a single line of hex output (up to BYTES_PER_LINE bytes).
 *
 * Format: OFFSET  | XX XX XX XX ... | ASCII... |
 *
 * Each byte is colorized:
 *   - Null (0x00)       → gray
 *   - Printable ASCII   → cyan
 *   - High bytes (>7F)  → red
 *   - Search matches    → green background
 */
static void print_hex_line(const unsigned char *buf, size_t len,
                           long offset, const unsigned char *match_map)
{
    size_t i;

    /* Offset column */
    printf("%s%08lx%s  ", COLOR_OFFSET, offset, COLOR_RESET);

    /* Hex bytes */
    for (i = 0; i < BYTES_PER_LINE; i++) {
        if (i == 8) printf(" ");  /* visual separator at midpoint */

        if (i < len) {
            const char *color;
            if (match_map && match_map[i])
                color = COLOR_MATCH;
            else if (buf[i] == 0x00)
                color = COLOR_NULL;
            else if (buf[i] > 0x7F)
                color = COLOR_HIGH;
            else if (isprint(buf[i]))
                color = COLOR_PRINT;
            else
                color = COLOR_RESET;

            printf("%s%02x%s ", color, buf[i], COLOR_RESET);
        } else {
            printf("   ");  /* pad incomplete lines */
        }
    }

    /* ASCII column */
    printf(" |");
    for (i = 0; i < len; i++) {
        if (match_map && match_map[i])
            printf("%s%c%s", COLOR_MATCH,
                   isprint(buf[i]) ? buf[i] : '.', COLOR_RESET);
        else if (isprint(buf[i]))
            printf("%s%c%s", COLOR_PRINT, buf[i], COLOR_RESET);
        else
            printf(".");
    }
    /* Pad ASCII column for short lines */
    for (i = len; i < BYTES_PER_LINE; i++)
        printf(" ");
    printf("|\n");
}

/*
 * Build a match map for search highlighting.
 * Sets match_map[i] = 1 for every byte position that is part of
 * a pattern match within the current line buffer.
 */
static void build_match_map(const unsigned char *buf, size_t len,
                            const char *pattern, size_t pat_len,
                            unsigned char *match_map)
{
    size_t i, j;

    memset(match_map, 0, len);
    if (!pattern || pat_len == 0 || pat_len > len) return;

    for (i = 0; i <= len - pat_len; i++) {
        if (memcmp(buf + i, pattern, pat_len) == 0) {
            for (j = 0; j < pat_len; j++)
                match_map[i + j] = 1;
        }
    }
}

int main(int argc, char *argv[])
{
    FILE *fp;
    long start_offset = 0;
    long byte_count = -1;  /* -1 = read entire file */
    const char *search_pattern = NULL;
    size_t pattern_len = 0;
    int opt;

    unsigned char buf[BYTES_PER_LINE];
    unsigned char match_map[BYTES_PER_LINE];
    size_t bytes_read;
    long total_read = 0;
    long current_offset;

    /* Parse command-line arguments */
    while ((opt = getopt(argc, argv, "o:n:s:h")) != -1) {
        switch (opt) {
        case 'o':
            start_offset = parse_offset(optarg);
            break;
        case 'n':
            byte_count = parse_offset(optarg);
            break;
        case 's':
            search_pattern = optarg;
            pattern_len = strlen(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no input file specified\n");
        usage(argv[0]);
    }

    /* Open the file */
    fp = fopen(argv[optind], "rb");
    if (!fp) {
        fprintf(stderr, "Error: cannot open '%s': %s\n",
                argv[optind], strerror(errno));
        return EXIT_FAILURE;
    }

    /* Get file size for display */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);

    /* Seek to start offset */
    if (start_offset > 0) {
        if (fseek(fp, start_offset, SEEK_SET) != 0) {
            fprintf(stderr, "Error: cannot seek to offset 0x%lx\n",
                    start_offset);
            fclose(fp);
            return EXIT_FAILURE;
        }
    } else {
        fseek(fp, 0, SEEK_SET);
    }

    /* Header */
    printf("File: %s (%ld bytes)\n", argv[optind], file_size);
    if (search_pattern)
        printf("Search: \"%s\"\n", search_pattern);
    printf("───────────────────────────────────────────────────────────\n");

    /* Read and display */
    current_offset = start_offset;
    while ((bytes_read = fread(buf, 1, BYTES_PER_LINE, fp)) > 0) {
        /* Check byte count limit */
        if (byte_count >= 0 && total_read >= byte_count)
            break;
        if (byte_count >= 0 && total_read + (long)bytes_read > byte_count)
            bytes_read = (size_t)(byte_count - total_read);

        /* Build match map if searching */
        if (search_pattern)
            build_match_map(buf, bytes_read, search_pattern,
                            pattern_len, match_map);

        print_hex_line(buf, bytes_read, current_offset,
                       search_pattern ? match_map : NULL);

        current_offset += bytes_read;
        total_read += bytes_read;
    }

    printf("───────────────────────────────────────────────────────────\n");
    printf("Displayed %ld bytes (offset 0x%lx — 0x%lx)\n",
           total_read, start_offset, current_offset);

    fclose(fp);
    return EXIT_SUCCESS;
}
