#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define PROGRAM_NAME "readmem"
#define PROGRAM_VERSION "0.6.0"
#define READ_CHUNK_SIZE (1024U * 1024U)
#define STOP_CHECK_GRANULARITY 65536U
#define DEFAULT_MIN_LENGTH 4U
#define DEFAULT_MAX_LENGTH 4096U
#define DEFAULT_MAX_RESULTS 100000U
#define DEFAULT_MAX_MEMORY UINT64_C(536870912)
#define DEFAULT_MAX_SCAN_SIZE UINT64_C(268435456)
#define DEFAULT_MAX_OUTPUT_SIZE UINT64_C(104857600)
#define DEFAULT_MAX_STATE_SIZE UINT64_C(134217728)
#define DEFAULT_MIN_FREE_SPACE UINT64_C(67108864)
#define DEFAULT_SCAN_TIMEOUT_NS UINT64_C(30000000000)
#define MIN_INTERVAL_NS UINT64_C(100000000)
#define INITIAL_SET_CAPACITY 128U

#if defined(__GNUC__) || defined(__clang__)
#define READMEM_PRINTF_LIKE(format_index, first_argument) \
    __attribute__((format(printf, format_index, first_argument)))
#else
#define READMEM_PRINTF_LIKE(format_index, first_argument)
#endif

enum exit_code {
    EXIT_OK = 0,
    EXIT_RUNTIME = 1,
    EXIT_USAGE_ERROR = 2,
    EXIT_PERMISSION_ERROR = 3,
    EXIT_TARGET_GONE = 4,
    EXIT_INCOMPLETE_SCAN = 5,
    EXIT_OUTPUT_ERROR = 6
};

typedef enum { FORMAT_TEXT, FORMAT_TSV, FORMAT_JSONL } output_format_t;
typedef enum { EMIT_ALL, EMIT_NEW, EMIT_CHANGES } emit_mode_t;
typedef enum { DEDUPE_NONE, DEDUPE_VALUE, DEDUPE_ADDRESS } dedupe_mode_t;
typedef enum { ENCODING_ASCII, ENCODING_UTF8, ENCODING_UTF16LE } encoding_t;
typedef enum { MATCH_ANY, MATCH_ALL } match_mode_t;
typedef enum { SCAN_STRATEGY_CONTINUE, SCAN_STRATEGY_RESTART } scan_strategy_t;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} string_list_t;

typedef struct {
    pid_t pid;
    bool interval_set;
    uint64_t interval_ns;
    bool duration_set;
    uint64_t duration_ns;
    uint64_t iterations;
    bool iterations_set;
    bool discover;
    const char *output_path;
    bool append_output;
    const char *state_path;
    output_format_t output_format;
    emit_mode_t emit_mode;
    dedupe_mode_t dedupe_mode;
    encoding_t encoding;
    size_t min_length;
    size_t max_length;
    size_t max_results;
    uint64_t max_memory;
    uint64_t max_scan_size;
    uint64_t max_output_size;
    uint64_t max_state_size;
    uint64_t min_free_space;
    uint64_t scan_timeout_ns;
    uint64_t target_starttime;
    bool best_effort;
    bool debug_output;
    int verbosity;
    match_mode_t match_mode;
    scan_strategy_t scan_strategy;
    string_list_t regex_patterns;
    string_list_t contains_patterns;
    string_list_t exclude_regex_patterns;
    string_list_t exclude_contains_patterns;
    string_list_t include_maps;
    string_list_t exclude_maps;
} options_t;

typedef struct {
    regex_t *items;
    size_t count;
} regex_list_t;

typedef struct {
    regex_list_t positive_regexes;
    regex_list_t negative_regexes;
    const string_list_t *positive_contains;
    const string_list_t *negative_contains;
    match_mode_t mode;
    bool discover;
} matcher_t;

typedef struct {
    uintptr_t start;
    uintptr_t end;
    char permissions[5];
    uintmax_t file_offset;
    unsigned int device_major;
    unsigned int device_minor;
    uintmax_t inode;
    char *name;
} memory_mapping_t;

typedef struct {
    uintptr_t address;
    char *mapping;
    char *value;
} match_t;

typedef struct {
    match_t **slots;
    size_t capacity;
    size_t count;
    dedupe_mode_t mode;
} match_set_t;

typedef struct {
    match_t **items;
    size_t count;
    size_t capacity;
    size_t limit;
    dedupe_mode_t mode;
    match_set_t index;
} match_collection_t;

typedef struct {
    FILE *stream;
    bool must_close;
    bool sync_file;
    output_format_t format;
    uint64_t bytes_written;
    uint64_t max_bytes;
    uint64_t min_free_bytes;
} output_t;

typedef struct {
    uint64_t bytes_read;
    uint64_t skipped_pages;
    uint64_t mappings_read;
    uint64_t unbacked_file_bytes;
    uint64_t limited_file_mappings;
    bool incomplete;
    bool reached_end;
    bool has_next_address;
    uintptr_t next_address;
    char *next_mapping;
} scan_stats_t;

typedef struct {
    encoding_t encoding;
    size_t min_chars;
    size_t max_chars;
    char *buffer;
    size_t length;
    size_t chars;
    size_t capacity;
    bool overflow;
    uintptr_t string_address;
    const char *mapping;
    matcher_t *matcher;
    match_collection_t *matches;
    int error;
    unsigned char utf8_sequence[4];
    size_t utf8_length;
    size_t utf8_expected;
    uint32_t utf8_codepoint;
    uint32_t utf8_minimum;
    uintptr_t utf8_address;
    bool utf16_have_byte;
    unsigned int utf16_alignment;
    unsigned char utf16_first_byte;
    uintptr_t utf16_unit_address;
    bool utf16_have_high_surrogate;
    uint16_t utf16_high_surrogate;
    uintptr_t utf16_high_address;
} string_scanner_t;

typedef struct {
    bool active;
    uintptr_t next_address;
    uintptr_t mapping_start;
    uintptr_t mapping_end;
    uintmax_t file_offset;
    unsigned int device_major;
    unsigned int device_minor;
    uintmax_t inode;
    char permissions[5];
    char *mapping_name;
    bool has_scanner;
    string_scanner_t scanner;
    bool has_alternate_scanner;
    string_scanner_t alternate_scanner;
} scan_cursor_t;

typedef enum {
    REGION_OK,
    REGION_PAGE_FAULT,
    REGION_TARGET_GONE,
    REGION_PERMISSION_DENIED,
    REGION_TIMEOUT,
    REGION_LIMIT,
    REGION_RESULT_LIMIT,
    REGION_STOPPED,
    REGION_FATAL
} region_result_t;

typedef enum {
    SCAN_COMPLETE,
    SCAN_MORE,
    SCAN_PARTIAL,
    SCAN_TARGET_EXITED,
    SCAN_PERMISSION_DENIED,
    SCAN_STOPPED,
    SCAN_FATAL
} scan_result_t;

typedef enum {
    OUTPUT_WRITE_ERROR = -1,
    OUTPUT_WRITE_OK = 0,
    OUTPUT_WRITE_LIMIT = 1
} output_write_result_t;

typedef enum {
    COMMIT_ERROR = -1,
    COMMIT_OK = 0,
    COMMIT_OUTPUT_LIMIT = 1
} commit_result_t;

static volatile sig_atomic_t stop_requested = 0;

static bool scan_timed_out(uint64_t started_ns, uint64_t timeout_ns);

static void handle_signal(int signo)
{
    (void)signo;
    stop_requested = 1;
}

static void log_message(const options_t *options, int level, const char *format, ...)
    READMEM_PRINTF_LIKE(3, 4);

static void log_message(const options_t *options, int level, const char *format, ...)
{
    va_list arguments;

    if (options->verbosity < level) {
        return;
    }
    va_start(arguments, format);
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    (void)vfprintf(stderr, format, arguments);
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
    va_end(arguments);
    (void)fputc('\n', stderr);
}

static void print_usage(FILE *stream)
{
    (void)fprintf(stream,
        "Usage: %s --pid PID (--regex PATTERN | --contains TEXT | --discover) [OPTIONS]\n"
        "\n"
        "Target and scheduling:\n"
        "  -p, --pid PID                 target process ID\n"
        "  -i, --interval DURATION       wait after each scan, then repeat it\n"
        "      --duration DURATION       stop scheduling scans after this time\n"
        "      --iterations N            number of scans; 0 means unlimited\n"
        "      --scan-timeout DURATION   soft time limit for one scan (default: 30s)\n"
        "      --max-scan-size SIZE      bytes read per scan (default: 256MiB)\n"
        "      --scan-strategy MODE      continue or restart (default: continue)\n"
        "      --max-memory SIZE         address-space limit (default: 512MiB)\n"
        "\n"
        "Matching:\n"
        "      --discover                emit candidate strings without a positive matcher\n"
        "  -e, --regex PATTERN           POSIX ERE for the whole string (repeatable)\n"
        "  -s, --contains TEXT           literal substring condition (repeatable)\n"
        "      --match-mode MODE         combine positive conditions: any or all\n"
        "      --exclude-regex PATTERN   reject a whole-string POSIX ERE (repeatable)\n"
        "      --exclude-contains TEXT   reject a literal substring (repeatable)\n"
        "      --encoding NAME           ascii, utf8, or utf16le (default: ascii)\n"
        "      --min-length N            minimum string length (default: %u)\n"
        "      --max-length N            maximum string length (default: %u)\n"
        "      --include-map REGEX       include mapping names matching REGEX (repeatable)\n"
        "      --exclude-map REGEX       exclude mapping names matching REGEX (repeatable)\n"
        "\n"
        "Output and state:\n"
        "  -o, --output FILE             create a new result FILE; '-' means stdout\n"
        "      --append                  append to an existing protected FILE\n"
        "      --format NAME             text, tsv, or jsonl (default: jsonl)\n"
        "      --emit MODE               all, new, or changes (default: new)\n"
        "      --dedupe MODE             none, value, or address (default: value)\n"
        "      --state-file FILE         persist deduplication state across restarts\n"
        "      --max-results N           in-memory result limit (default: %u)\n"
        "      --max-output-size SIZE    output limit (default: 100MiB)\n"
        "      --max-state-size SIZE     state-file limit (default: 128MiB)\n"
        "      --min-free-space SIZE     filesystem reserve (default: 64MiB)\n"
        "      --debug                   include full match metadata and scan summaries\n"
        "\n"
        "Error handling:\n"
        "      --best-effort             continue after inaccessible remote pages\n"
        "  -v, --verbose                 print per-scan statistics\n"
        "  -q, --quiet                   suppress warnings and informational messages\n"
        "  -h, --help                    show this help\n"
        "      --version                 show program version\n",
        PROGRAM_NAME, DEFAULT_MIN_LENGTH, DEFAULT_MAX_LENGTH, DEFAULT_MAX_RESULTS);
}

static bool parse_unsigned(const char *text, uint64_t *value)
{
    char *end = NULL;
    uintmax_t parsed;

    if (text == NULL || *text == '\0' || *text == '-') {
        return false;
    }
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT64_MAX) {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

static bool parse_pid(const char *text, pid_t *pid)
{
    uint64_t parsed;

    if (!parse_unsigned(text, &parsed) || parsed == 0 || parsed > INT32_MAX) {
        return false;
    }
    *pid = (pid_t)parsed;
    return true;
}

static bool parse_duration_ns(const char *text, uint64_t *nanoseconds)
{
    char *end = NULL;
    double number;
    double multiplier;
    double result;

    if (text == NULL || *text == '\0' || *text == '-') {
        return false;
    }
    errno = 0;
    number = strtod(text, &end);
    if (errno != 0 || end == text || !isfinite(number) || number <= 0.0) {
        return false;
    }
    if (strcmp(end, "ns") == 0) {
        multiplier = 1.0;
    } else if (strcmp(end, "us") == 0) {
        multiplier = 1000.0;
    } else if (strcmp(end, "ms") == 0) {
        multiplier = 1000000.0;
    } else if (strcmp(end, "s") == 0 || *end == '\0') {
        multiplier = 1000000000.0;
    } else if (strcmp(end, "m") == 0) {
        multiplier = 60.0 * 1000000000.0;
    } else if (strcmp(end, "h") == 0) {
        multiplier = 3600.0 * 1000000000.0;
    } else {
        return false;
    }
    result = number * multiplier;
    if (!isfinite(result) || result < 1.0 || result >= 18446744073709551616.0) {
        return false;
    }
    *nanoseconds = (uint64_t)result;
    return true;
}

static bool parse_size_bytes(const char *text, uint64_t *bytes)
{
    char *end = NULL;
    uintmax_t parsed;
    uint64_t multiplier;

    if (text == NULL || *text == '\0' || *text == '-') return false;
    errno = 0;
    parsed = strtoumax(text, &end, 10);
    if (errno != 0 || end == text || parsed == 0 || parsed > UINT64_MAX) return false;
    if (*end == '\0' || strcmp(end, "B") == 0) multiplier = UINT64_C(1);
    else if (strcmp(end, "K") == 0 || strcmp(end, "KB") == 0 ||
        strcmp(end, "KiB") == 0) multiplier = UINT64_C(1024);
    else if (strcmp(end, "M") == 0 || strcmp(end, "MB") == 0 ||
        strcmp(end, "MiB") == 0) multiplier = UINT64_C(1024) * UINT64_C(1024);
    else if (strcmp(end, "G") == 0 || strcmp(end, "GB") == 0 ||
        strcmp(end, "GiB") == 0)
        multiplier = UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024);
    else if (strcmp(end, "T") == 0 || strcmp(end, "TB") == 0 ||
        strcmp(end, "TiB") == 0)
        multiplier = UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024);
    else return false;
    if ((uint64_t)parsed > UINT64_MAX / multiplier) return false;
    *bytes = (uint64_t)parsed * multiplier;
    return true;
}

static int string_list_add(string_list_t *list, char *item)
{
    char **new_items;
    size_t new_capacity;

    if (list->count == list->capacity) {
        new_capacity = list->capacity == 0 ? 4U : list->capacity * 2U;
        if (new_capacity < list->capacity || new_capacity > SIZE_MAX / sizeof(*new_items)) {
            errno = ENOMEM;
            return -1;
        }
        new_items = realloc(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return -1;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = item;
    return 0;
}

static const char *format_name(output_format_t format)
{
    switch (format) {
    case FORMAT_TEXT: return "text";
    case FORMAT_TSV: return "tsv";
    case FORMAT_JSONL: return "jsonl";
    }
    return "unknown";
}

static const char *emit_name(emit_mode_t mode)
{
    switch (mode) {
    case EMIT_ALL: return "all";
    case EMIT_NEW: return "new";
    case EMIT_CHANGES: return "changes";
    }
    return "unknown";
}

static const char *dedupe_name(dedupe_mode_t mode)
{
    switch (mode) {
    case DEDUPE_NONE: return "none";
    case DEDUPE_VALUE: return "value";
    case DEDUPE_ADDRESS: return "address";
    }
    return "unknown";
}

static const char *encoding_name(encoding_t encoding)
{
    switch (encoding) {
    case ENCODING_ASCII: return "ascii";
    case ENCODING_UTF8: return "utf8";
    case ENCODING_UTF16LE: return "utf16le";
    }
    return "unknown";
}

static const char *match_mode_name(match_mode_t mode)
{
    switch (mode) {
    case MATCH_ANY: return "any";
    case MATCH_ALL: return "all";
    }
    return "unknown";
}

static const char *scan_strategy_name(scan_strategy_t strategy)
{
    switch (strategy) {
    case SCAN_STRATEGY_CONTINUE: return "continue";
    case SCAN_STRATEGY_RESTART: return "restart";
    }
    return "unknown";
}

static int parse_options(int argc, char **argv, options_t *options)
{
    enum {
        OPT_ITERATIONS = 1000,
        OPT_DURATION,
        OPT_SCAN_TIMEOUT,
        OPT_DISCOVER,
        OPT_ENCODING,
        OPT_MIN_LENGTH,
        OPT_MAX_LENGTH,
        OPT_INCLUDE_MAP,
        OPT_EXCLUDE_MAP,
        OPT_FORMAT,
        OPT_EMIT,
        OPT_DEDUPE,
        OPT_STATE_FILE,
        OPT_APPEND,
        OPT_MAX_RESULTS,
        OPT_MAX_MEMORY,
        OPT_MAX_SCAN_SIZE,
        OPT_SCAN_STRATEGY,
        OPT_MAX_OUTPUT_SIZE,
        OPT_MAX_STATE_SIZE,
        OPT_MIN_FREE_SPACE,
        OPT_BEST_EFFORT,
        OPT_MATCH_MODE,
        OPT_EXCLUDE_REGEX,
        OPT_EXCLUDE_CONTAINS,
        OPT_DEBUG,
        OPT_VERSION
    };
    static const struct option long_options[] = {
        { "pid", required_argument, NULL, 'p' },
        { "interval", required_argument, NULL, 'i' },
        { "duration", required_argument, NULL, OPT_DURATION },
        { "iterations", required_argument, NULL, OPT_ITERATIONS },
        { "scan-timeout", required_argument, NULL, OPT_SCAN_TIMEOUT },
        { "discover", no_argument, NULL, OPT_DISCOVER },
        { "regex", required_argument, NULL, 'e' },
        { "contains", required_argument, NULL, 's' },
        { "match-mode", required_argument, NULL, OPT_MATCH_MODE },
        { "exclude-regex", required_argument, NULL, OPT_EXCLUDE_REGEX },
        { "exclude-contains", required_argument, NULL, OPT_EXCLUDE_CONTAINS },
        { "encoding", required_argument, NULL, OPT_ENCODING },
        { "min-length", required_argument, NULL, OPT_MIN_LENGTH },
        { "max-length", required_argument, NULL, OPT_MAX_LENGTH },
        { "include-map", required_argument, NULL, OPT_INCLUDE_MAP },
        { "exclude-map", required_argument, NULL, OPT_EXCLUDE_MAP },
        { "output", required_argument, NULL, 'o' },
        { "format", required_argument, NULL, OPT_FORMAT },
        { "emit", required_argument, NULL, OPT_EMIT },
        { "dedupe", required_argument, NULL, OPT_DEDUPE },
        { "state-file", required_argument, NULL, OPT_STATE_FILE },
        { "append", no_argument, NULL, OPT_APPEND },
        { "max-results", required_argument, NULL, OPT_MAX_RESULTS },
        { "max-memory", required_argument, NULL, OPT_MAX_MEMORY },
        { "max-scan-size", required_argument, NULL, OPT_MAX_SCAN_SIZE },
        { "scan-strategy", required_argument, NULL, OPT_SCAN_STRATEGY },
        { "max-output-size", required_argument, NULL, OPT_MAX_OUTPUT_SIZE },
        { "max-state-size", required_argument, NULL, OPT_MAX_STATE_SIZE },
        { "min-free-space", required_argument, NULL, OPT_MIN_FREE_SPACE },
        { "best-effort", no_argument, NULL, OPT_BEST_EFFORT },
        { "debug", no_argument, NULL, OPT_DEBUG },
        { "verbose", no_argument, NULL, 'v' },
        { "quiet", no_argument, NULL, 'q' },
        { "help", no_argument, NULL, 'h' },
        { "version", no_argument, NULL, OPT_VERSION },
        { NULL, 0, NULL, 0 }
    };
    int option;
    uint64_t parsed;

    memset(options, 0, sizeof(*options));
    options->output_path = "-";
    options->output_format = FORMAT_JSONL;
    options->emit_mode = EMIT_NEW;
    options->dedupe_mode = DEDUPE_VALUE;
    options->encoding = ENCODING_ASCII;
    options->min_length = DEFAULT_MIN_LENGTH;
    options->max_length = DEFAULT_MAX_LENGTH;
    options->max_results = DEFAULT_MAX_RESULTS;
    options->max_memory = DEFAULT_MAX_MEMORY;
    options->max_scan_size = DEFAULT_MAX_SCAN_SIZE;
    options->max_output_size = DEFAULT_MAX_OUTPUT_SIZE;
    options->max_state_size = DEFAULT_MAX_STATE_SIZE;
    options->min_free_space = DEFAULT_MIN_FREE_SPACE;
    options->scan_timeout_ns = DEFAULT_SCAN_TIMEOUT_NS;
    options->verbosity = 1;
    options->match_mode = MATCH_ANY;
    options->scan_strategy = SCAN_STRATEGY_CONTINUE;

    while ((option = getopt_long(argc, argv, "p:i:e:s:o:vqh", long_options, NULL)) != -1) {
        switch (option) {
        case 'p':
            if (!parse_pid(optarg, &options->pid)) {
                (void)fprintf(stderr, "%s: invalid PID: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case 'i':
            if (!parse_duration_ns(optarg, &options->interval_ns)) {
                (void)fprintf(stderr, "%s: invalid interval: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->interval_set = true;
            break;
        case 'e':
            if (string_list_add(&options->regex_patterns, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case 's':
            if (string_list_add(&options->contains_patterns, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case 'o': options->output_path = optarg; break;
        case 'v': options->verbosity = 2; break;
        case 'q': options->verbosity = 0; break;
        case 'h': print_usage(stdout); exit(EXIT_OK);
        case OPT_ITERATIONS:
            if (!parse_unsigned(optarg, &options->iterations)) {
                (void)fprintf(stderr, "%s: invalid iteration count: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->iterations_set = true;
            break;
        case OPT_DURATION:
            if (!parse_duration_ns(optarg, &options->duration_ns)) {
                (void)fprintf(stderr, "%s: invalid duration: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->duration_set = true;
            break;
        case OPT_SCAN_TIMEOUT:
            if (!parse_duration_ns(optarg, &options->scan_timeout_ns)) {
                (void)fprintf(stderr, "%s: invalid scan timeout: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_DISCOVER: options->discover = true; break;
        case OPT_ENCODING:
            if (strcmp(optarg, "ascii") == 0) options->encoding = ENCODING_ASCII;
            else if (strcmp(optarg, "utf8") == 0) options->encoding = ENCODING_UTF8;
            else if (strcmp(optarg, "utf16le") == 0) options->encoding = ENCODING_UTF16LE;
            else {
                (void)fprintf(stderr, "%s: unknown encoding: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_MIN_LENGTH:
            if (!parse_unsigned(optarg, &parsed) || parsed == 0 || parsed > SIZE_MAX) {
                (void)fprintf(stderr, "%s: invalid minimum length: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->min_length = (size_t)parsed;
            break;
        case OPT_MAX_LENGTH:
            if (!parse_unsigned(optarg, &parsed) || parsed == 0 || parsed > SIZE_MAX) {
                (void)fprintf(stderr, "%s: invalid maximum length: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->max_length = (size_t)parsed;
            break;
        case OPT_INCLUDE_MAP:
            if (string_list_add(&options->include_maps, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case OPT_EXCLUDE_MAP:
            if (string_list_add(&options->exclude_maps, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case OPT_FORMAT:
            if (strcmp(optarg, "text") == 0) options->output_format = FORMAT_TEXT;
            else if (strcmp(optarg, "tsv") == 0) options->output_format = FORMAT_TSV;
            else if (strcmp(optarg, "jsonl") == 0) options->output_format = FORMAT_JSONL;
            else {
                (void)fprintf(stderr, "%s: unknown output format: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_EMIT:
            if (strcmp(optarg, "all") == 0) options->emit_mode = EMIT_ALL;
            else if (strcmp(optarg, "new") == 0) options->emit_mode = EMIT_NEW;
            else if (strcmp(optarg, "changes") == 0) options->emit_mode = EMIT_CHANGES;
            else {
                (void)fprintf(stderr, "%s: unknown emit mode: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_DEDUPE:
            if (strcmp(optarg, "none") == 0) options->dedupe_mode = DEDUPE_NONE;
            else if (strcmp(optarg, "value") == 0) options->dedupe_mode = DEDUPE_VALUE;
            else if (strcmp(optarg, "address") == 0) options->dedupe_mode = DEDUPE_ADDRESS;
            else {
                (void)fprintf(stderr, "%s: unknown dedupe mode: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_STATE_FILE: options->state_path = optarg; break;
        case OPT_APPEND: options->append_output = true; break;
        case OPT_MAX_RESULTS:
            if (!parse_unsigned(optarg, &parsed) || parsed == 0 || parsed > SIZE_MAX) {
                (void)fprintf(stderr, "%s: invalid result limit: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            options->max_results = (size_t)parsed;
            break;
        case OPT_MAX_MEMORY:
            if (!parse_size_bytes(optarg, &options->max_memory)) {
                (void)fprintf(stderr, "%s: invalid memory limit: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_MAX_SCAN_SIZE:
            if (!parse_size_bytes(optarg, &options->max_scan_size)) {
                (void)fprintf(stderr, "%s: invalid scan size limit: %s\n",
                    PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_SCAN_STRATEGY:
            if (strcmp(optarg, "continue") == 0)
                options->scan_strategy = SCAN_STRATEGY_CONTINUE;
            else if (strcmp(optarg, "restart") == 0)
                options->scan_strategy = SCAN_STRATEGY_RESTART;
            else {
                (void)fprintf(stderr, "%s: unknown scan strategy: %s\n",
                    PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_MAX_OUTPUT_SIZE:
            if (!parse_size_bytes(optarg, &options->max_output_size)) {
                (void)fprintf(stderr, "%s: invalid output size limit: %s\n",
                    PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_MAX_STATE_SIZE:
            if (!parse_size_bytes(optarg, &options->max_state_size)) {
                (void)fprintf(stderr, "%s: invalid state size limit: %s\n",
                    PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_MIN_FREE_SPACE:
            if (!parse_size_bytes(optarg, &options->min_free_space)) {
                (void)fprintf(stderr, "%s: invalid free-space reserve: %s\n",
                    PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_BEST_EFFORT: options->best_effort = true; break;
        case OPT_DEBUG: options->debug_output = true; break;
        case OPT_MATCH_MODE:
            if (strcmp(optarg, "any") == 0) options->match_mode = MATCH_ANY;
            else if (strcmp(optarg, "all") == 0) options->match_mode = MATCH_ALL;
            else {
                (void)fprintf(stderr, "%s: unknown match mode: %s\n", PROGRAM_NAME, optarg);
                return -1;
            }
            break;
        case OPT_EXCLUDE_REGEX:
            if (string_list_add(&options->exclude_regex_patterns, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case OPT_EXCLUDE_CONTAINS:
            if (string_list_add(&options->exclude_contains_patterns, optarg) != 0) {
                perror("realloc");
                return -1;
            }
            break;
        case OPT_VERSION: (void)printf("%s %s\n", PROGRAM_NAME, PROGRAM_VERSION); exit(EXIT_OK);
        default: return -1;
        }
    }

    if (optind != argc) {
        (void)fprintf(stderr, "%s: unexpected argument: %s\n", PROGRAM_NAME, argv[optind]);
        return -1;
    }
    if (options->pid <= 0) {
        (void)fprintf(stderr, "%s: --pid is required\n", PROGRAM_NAME);
        return -1;
    }
    if (!options->discover && options->regex_patterns.count == 0 &&
        options->contains_patterns.count == 0) {
        (void)fprintf(stderr,
            "%s: specify at least one --regex or --contains condition, or use --discover\n",
            PROGRAM_NAME);
        return -1;
    }
    if (options->discover &&
        (options->regex_patterns.count != 0 || options->contains_patterns.count != 0)) {
        (void)fprintf(stderr,
            "%s: --discover cannot be combined with --regex or --contains\n", PROGRAM_NAME);
        return -1;
    }
    {
        size_t i;
        for (i = 0; i < options->regex_patterns.count; ++i) {
            if (*options->regex_patterns.items[i] == '\0') {
                (void)fprintf(stderr, "%s: --regex cannot be empty\n", PROGRAM_NAME);
                return -1;
            }
        }
        for (i = 0; i < options->contains_patterns.count; ++i) {
            if (*options->contains_patterns.items[i] == '\0') {
                (void)fprintf(stderr, "%s: --contains cannot be empty\n", PROGRAM_NAME);
                return -1;
            }
        }
        for (i = 0; i < options->exclude_regex_patterns.count; ++i) {
            if (*options->exclude_regex_patterns.items[i] == '\0') {
                (void)fprintf(stderr, "%s: --exclude-regex cannot be empty\n", PROGRAM_NAME);
                return -1;
            }
        }
        for (i = 0; i < options->exclude_contains_patterns.count; ++i) {
            if (*options->exclude_contains_patterns.items[i] == '\0') {
                (void)fprintf(stderr, "%s: --exclude-contains cannot be empty\n", PROGRAM_NAME);
                return -1;
            }
        }
    }
    if (*options->output_path == '\0' ||
        (options->state_path != NULL && *options->state_path == '\0')) {
        (void)fprintf(stderr, "%s: output and state paths cannot be empty\n", PROGRAM_NAME);
        return -1;
    }
    if (options->discover && strcmp(options->output_path, "-") == 0) {
        (void)fprintf(stderr, "%s: --discover requires --output FILE\n", PROGRAM_NAME);
        return -1;
    }
    if (options->append_output && strcmp(options->output_path, "-") == 0) {
        (void)fprintf(stderr, "%s: --append requires --output FILE\n", PROGRAM_NAME);
        return -1;
    }
    if (options->min_length > options->max_length) {
        (void)fprintf(stderr, "%s: --min-length cannot exceed --max-length\n", PROGRAM_NAME);
        return -1;
    }
    if (options->max_length > (SIZE_MAX - 1U) / 4U) {
        (void)fprintf(stderr, "%s: --max-length is too large\n", PROGRAM_NAME);
        return -1;
    }
    if (options->emit_mode != EMIT_ALL && options->dedupe_mode == DEDUPE_NONE) {
        (void)fprintf(stderr, "%s: --emit %s requires --dedupe value or address\n",
            PROGRAM_NAME, emit_name(options->emit_mode));
        return -1;
    }
    if (options->state_path != NULL && options->emit_mode == EMIT_ALL) {
        (void)fprintf(stderr, "%s: --state-file requires --emit new or changes\n", PROGRAM_NAME);
        return -1;
    }
    if (options->debug_output && options->output_format != FORMAT_JSONL) {
        (void)fprintf(stderr, "%s: --debug requires --format jsonl\n", PROGRAM_NAME);
        return -1;
    }
    if (options->state_path != NULL && strcmp(options->state_path, options->output_path) == 0) {
        (void)fprintf(stderr, "%s: output and state files must be different\n", PROGRAM_NAME);
        return -1;
    }
    if (options->duration_set && !options->interval_set) {
        (void)fprintf(stderr, "%s: --duration requires --interval\n", PROGRAM_NAME);
        return -1;
    }
    if (options->interval_set && options->interval_ns < MIN_INTERVAL_NS) {
        (void)fprintf(stderr, "%s: --interval must be at least 100ms\n", PROGRAM_NAME);
        return -1;
    }
    if (!options->iterations_set) {
        options->iterations = options->interval_set ? 0U : 1U;
    } else if (!options->interval_set && options->iterations != 1U) {
        (void)fprintf(stderr, "%s: --iterations other than 1 requires --interval\n", PROGRAM_NAME);
        return -1;
    }
    if (options->discover && options->interval_set && options->iterations == 0U &&
        !options->duration_set) {
        (void)fprintf(stderr,
            "%s: periodic --discover requires --duration or a finite --iterations value\n",
            PROGRAM_NAME);
        return -1;
    }
    return 0;
}

static int regex_list_compile(regex_list_t *compiled, const string_list_t *patterns,
    const char *option_name, int flags)
{
    size_t i;
    int result;
    char message[256];

    memset(compiled, 0, sizeof(*compiled));
    if (patterns->count == 0) return 0;
    compiled->items = calloc(patterns->count, sizeof(*compiled->items));
    if (compiled->items == NULL) return -1;
    for (i = 0; i < patterns->count; ++i) {
        result = regcomp(&compiled->items[i], patterns->items[i], flags);
        if (result != 0) {
            (void)regerror(result, &compiled->items[i], message, sizeof(message));
            (void)fprintf(stderr, "%s: invalid %s expression '%s': %s\n",
                PROGRAM_NAME, option_name, patterns->items[i], message);
            while (i > 0) regfree(&compiled->items[--i]);
            free(compiled->items);
            compiled->items = NULL;
            return -1;
        }
        compiled->count++;
    }
    return 0;
}

static void regex_list_destroy(regex_list_t *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) regfree(&list->items[i]);
    free(list->items);
}

static int regex_list_any(const regex_list_t *list, const char *value, bool *matched)
{
    size_t i;
    *matched = false;
    for (i = 0; i < list->count; ++i) {
        int result = regexec(&list->items[i], value, 0, NULL, 0);
        if (result == 0) {
            *matched = true;
            return 0;
        }
        if (result != REG_NOMATCH) {
            errno = result == REG_ESPACE ? ENOMEM : EINVAL;
            return -1;
        }
    }
    return 0;
}

static int regex_full_matches(const regex_t *regex, const char *value, size_t length,
    bool *matched)
{
    regmatch_t match = { 0, 0 };
    int result = regexec(regex, value, 1, &match, 0);
    if (result != 0 && result != REG_NOMATCH) {
        errno = result == REG_ESPACE ? ENOMEM : EINVAL;
        return -1;
    }
    *matched = result == 0 && match.rm_so == 0 && match.rm_eo >= 0 &&
        (size_t)match.rm_eo == length;
    return 0;
}

static int matcher_init(matcher_t *matcher, const options_t *options)
{
    memset(matcher, 0, sizeof(*matcher));
    matcher->positive_contains = &options->contains_patterns;
    matcher->negative_contains = &options->exclude_contains_patterns;
    matcher->mode = options->match_mode;
    matcher->discover = options->discover;
    if (regex_list_compile(&matcher->positive_regexes, &options->regex_patterns,
            "--regex", REG_EXTENDED) != 0) {
        return -1;
    }
    if (regex_list_compile(&matcher->negative_regexes, &options->exclude_regex_patterns,
            "--exclude-regex", REG_EXTENDED) != 0) {
        regex_list_destroy(&matcher->positive_regexes);
        memset(&matcher->positive_regexes, 0, sizeof(matcher->positive_regexes));
        return -1;
    }
    return 0;
}

static void matcher_destroy(matcher_t *matcher)
{
    regex_list_destroy(&matcher->negative_regexes);
    regex_list_destroy(&matcher->positive_regexes);
}

static int matcher_matches(matcher_t *matcher, const char *value, size_t length, bool *matched)
{
    size_t i;
    bool condition;

    for (i = 0; i < matcher->negative_regexes.count; ++i) {
        if (regex_full_matches(&matcher->negative_regexes.items[i], value, length,
                &condition) != 0) return -1;
        if (condition) { *matched = false; return 0; }
    }
    for (i = 0; i < matcher->negative_contains->count; ++i) {
        if (strstr(value, matcher->negative_contains->items[i]) != NULL) {
            *matched = false;
            return 0;
        }
    }
    if (matcher->discover) { *matched = true; return 0; }
    if (matcher->mode == MATCH_ANY) {
        for (i = 0; i < matcher->positive_regexes.count; ++i) {
            if (regex_full_matches(&matcher->positive_regexes.items[i], value, length,
                    &condition) != 0) return -1;
            if (condition) { *matched = true; return 0; }
        }
        for (i = 0; i < matcher->positive_contains->count; ++i) {
            if (strstr(value, matcher->positive_contains->items[i]) != NULL) {
                *matched = true;
                return 0;
            }
        }
        *matched = false;
        return 0;
    }
    for (i = 0; i < matcher->positive_regexes.count; ++i) {
        if (regex_full_matches(&matcher->positive_regexes.items[i], value, length,
                &condition) != 0) return -1;
        if (!condition) { *matched = false; return 0; }
    }
    for (i = 0; i < matcher->positive_contains->count; ++i) {
        if (strstr(value, matcher->positive_contains->items[i]) == NULL) {
            *matched = false;
            return 0;
        }
    }
    *matched = true;
    return 0;
}

static uint64_t hash_bytes(uint64_t hash, const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i = 0; i < length; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t hash_string_list(uint64_t hash, const char *tag, const string_list_t *list)
{
    size_t i;
    for (i = 0; i < list->count; ++i) {
        hash = hash_bytes(hash, (const unsigned char *)tag, strlen(tag) + 1U);
        hash = hash_bytes(hash, (const unsigned char *)list->items[i],
            strlen(list->items[i]) + 1U);
    }
    return hash;
}

static uint64_t options_state_hash(const options_t *options)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    uint64_t scalar;
    const char *mode_name = match_mode_name(options->match_mode);

    hash = hash_bytes(hash, (const unsigned char *)mode_name, strlen(mode_name) + 1U);
    if (options->discover)
        hash = hash_bytes(hash, (const unsigned char *)"discover", sizeof("discover"));
    hash = hash_string_list(hash, "regex", &options->regex_patterns);
    hash = hash_string_list(hash, "contains", &options->contains_patterns);
    hash = hash_string_list(hash, "exclude-regex", &options->exclude_regex_patterns);
    hash = hash_string_list(hash, "exclude-contains", &options->exclude_contains_patterns);
    hash = hash_bytes(hash, (const unsigned char *)encoding_name(options->encoding),
        strlen(encoding_name(options->encoding)) + 1U);
    scalar = (uint64_t)options->pid;
    hash = hash_bytes(hash, (const unsigned char *)&scalar, sizeof(scalar));
    scalar = options->target_starttime;
    hash = hash_bytes(hash, (const unsigned char *)&scalar, sizeof(scalar));
    scalar = (uint64_t)options->min_length;
    hash = hash_bytes(hash, (const unsigned char *)&scalar, sizeof(scalar));
    scalar = (uint64_t)options->max_length;
    hash = hash_bytes(hash, (const unsigned char *)&scalar, sizeof(scalar));
    hash = hash_string_list(hash, "include-map", &options->include_maps);
    hash = hash_string_list(hash, "exclude-map", &options->exclude_maps);
    return hash;
}

static uint64_t match_hash(const match_t *match, dedupe_mode_t mode)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    if (mode == DEDUPE_ADDRESS) {
        uintptr_t address = match->address;
        hash = hash_bytes(hash, (const unsigned char *)&address, sizeof(address));
    }
    return hash_bytes(hash, (const unsigned char *)match->value, strlen(match->value));
}

static bool match_key_equal(const match_t *left, const match_t *right, dedupe_mode_t mode)
{
    if (mode == DEDUPE_ADDRESS && left->address != right->address) return false;
    return strcmp(left->value, right->value) == 0;
}

static match_t *match_create(uintptr_t address, const char *mapping, const char *value)
{
    match_t *match = calloc(1, sizeof(*match));
    if (match == NULL) return NULL;
    match->mapping = strdup(mapping);
    match->value = strdup(value);
    if (match->mapping == NULL || match->value == NULL) {
        free(match->mapping);
        free(match->value);
        free(match);
        return NULL;
    }
    match->address = address;
    return match;
}

static match_t *match_clone(const match_t *source)
{
    return match_create(source->address, source->mapping, source->value);
}

static void match_destroy(match_t *match)
{
    if (match != NULL) {
        free(match->mapping);
        free(match->value);
        free(match);
    }
}

static int match_set_init(match_set_t *set, dedupe_mode_t mode)
{
    memset(set, 0, sizeof(*set));
    set->capacity = INITIAL_SET_CAPACITY;
    set->mode = mode;
    set->slots = calloc(set->capacity, sizeof(*set->slots));
    return set->slots == NULL ? -1 : 0;
}

static void match_set_destroy(match_set_t *set, bool destroy_matches)
{
    size_t i;
    if (destroy_matches) {
        for (i = 0; i < set->capacity; ++i) match_destroy(set->slots[i]);
    }
    free(set->slots);
    memset(set, 0, sizeof(*set));
}

static int match_set_rehash(match_set_t *set)
{
    match_t **new_slots;
    size_t new_capacity;
    size_t i;

    if (set->capacity > SIZE_MAX / 2U) {
        errno = ENOMEM;
        return -1;
    }
    new_capacity = set->capacity * 2U;
    new_slots = calloc(new_capacity, sizeof(*new_slots));
    if (new_slots == NULL) return -1;
    for (i = 0; i < set->capacity; ++i) {
        match_t *match = set->slots[i];
        size_t slot;
        if (match == NULL) continue;
        slot = (size_t)(match_hash(match, set->mode) & (new_capacity - 1U));
        while (new_slots[slot] != NULL) slot = (slot + 1U) & (new_capacity - 1U);
        new_slots[slot] = match;
    }
    free(set->slots);
    set->slots = new_slots;
    set->capacity = new_capacity;
    return 0;
}

static match_t *match_set_find(const match_set_t *set, const match_t *needle)
{
    size_t slot;
    if (set->slots == NULL) return NULL;
    slot = (size_t)(match_hash(needle, set->mode) & (set->capacity - 1U));
    while (set->slots[slot] != NULL) {
        if (match_key_equal(set->slots[slot], needle, set->mode)) return set->slots[slot];
        slot = (slot + 1U) & (set->capacity - 1U);
    }
    return NULL;
}

static int match_set_insert(match_set_t *set, match_t *match, bool *inserted)
{
    size_t slot;
    size_t rehash_threshold;
    *inserted = false;
    rehash_threshold = (set->capacity / 10U) * 7U;
    if (set->count >= rehash_threshold && match_set_rehash(set) != 0) {
        return -1;
    }
    slot = (size_t)(match_hash(match, set->mode) & (set->capacity - 1U));
    while (set->slots[slot] != NULL) {
        if (match_key_equal(set->slots[slot], match, set->mode)) return 0;
        slot = (slot + 1U) & (set->capacity - 1U);
    }
    set->slots[slot] = match;
    set->count++;
    *inserted = true;
    return 0;
}

static int collection_init(match_collection_t *collection, dedupe_mode_t mode, size_t limit)
{
    memset(collection, 0, sizeof(*collection));
    collection->mode = mode;
    collection->limit = limit;
    if (mode != DEDUPE_NONE && match_set_init(&collection->index, mode) != 0) return -1;
    return 0;
}

static void collection_destroy(match_collection_t *collection)
{
    size_t i;
    if (collection->mode != DEDUPE_NONE) match_set_destroy(&collection->index, false);
    for (i = 0; i < collection->count; ++i) match_destroy(collection->items[i]);
    free(collection->items);
    memset(collection, 0, sizeof(*collection));
}

static int collection_reserve(match_collection_t *collection)
{
    match_t **new_items;
    size_t new_capacity;
    if (collection->count < collection->capacity) return 0;
    new_capacity = collection->capacity == 0 ? 128U : collection->capacity * 2U;
    if (new_capacity < collection->capacity || new_capacity > SIZE_MAX / sizeof(*new_items)) {
        errno = ENOMEM;
        return -1;
    }
    new_items = realloc(collection->items, new_capacity * sizeof(*new_items));
    if (new_items == NULL) return -1;
    collection->items = new_items;
    collection->capacity = new_capacity;
    return 0;
}

static int collection_add(match_collection_t *collection, uintptr_t address,
    const char *mapping, const char *value)
{
    match_t *match = match_create(address, mapping, value);
    bool inserted = true;
    if (match == NULL) return -1;
    if (collection->mode != DEDUPE_NONE && match_set_find(&collection->index, match) != NULL) {
        match_destroy(match);
        return 0;
    }
    if (collection->count >= collection->limit) {
        match_destroy(match);
        errno = EOVERFLOW;
        return -1;
    }
    if (collection_reserve(collection) != 0) {
        match_destroy(match);
        return -1;
    }
    if (collection->mode != DEDUPE_NONE &&
        match_set_insert(&collection->index, match, &inserted) != 0) {
        match_destroy(match);
        return -1;
    }
    if (!inserted) {
        match_destroy(match);
        return 0;
    }
    collection->items[collection->count++] = match;
    return 0;
}

static int collection_merge(match_collection_t *destination,
    const match_collection_t *source)
{
    size_t i;
    for (i = 0; i < source->count; ++i) {
        const match_t *match = source->items[i];
        if (collection_add(destination, match->address, match->mapping,
                match->value) != 0) return -1;
    }
    return 0;
}

static bool unicode_printable(uint32_t codepoint)
{
    if (codepoint >= UINT32_C(0x20) && codepoint <= UINT32_C(0x7e)) return true;
    if (codepoint < UINT32_C(0xa0) || codepoint > UINT32_C(0x10ffff)) return false;
    if (codepoint >= UINT32_C(0xd800) && codepoint <= UINT32_C(0xdfff)) return false;
    if (codepoint >= UINT32_C(0xfdd0) && codepoint <= UINT32_C(0xfdef)) return false;
    if ((codepoint & UINT32_C(0xffff)) == UINT32_C(0xfffe) ||
        (codepoint & UINT32_C(0xffff)) == UINT32_C(0xffff)) return false;
    return true;
}

static int scanner_init(string_scanner_t *scanner, const options_t *options,
    const char *mapping, matcher_t *matcher, match_collection_t *matches)
{
    size_t capacity = options->max_length * 4U + 1U;
    memset(scanner, 0, sizeof(*scanner));
    scanner->buffer = malloc(capacity);
    if (scanner->buffer == NULL) return -1;
    scanner->capacity = capacity;
    scanner->encoding = options->encoding;
    scanner->min_chars = options->min_length;
    scanner->max_chars = options->max_length;
    scanner->mapping = mapping;
    scanner->matcher = matcher;
    scanner->matches = matches;
    return 0;
}

static void scanner_reset_string(string_scanner_t *scanner)
{
    scanner->length = 0;
    scanner->chars = 0;
    scanner->overflow = false;
    scanner->string_address = 0;
}

static int scanner_finish_string(string_scanner_t *scanner)
{
    if (!scanner->overflow && scanner->chars >= scanner->min_chars && scanner->length > 0) {
        bool matched;
        scanner->buffer[scanner->length] = '\0';
        if (matcher_matches(scanner->matcher, scanner->buffer, scanner->length,
                &matched) != 0) {
            scanner->error = errno;
            return -1;
        }
        if (matched && collection_add(scanner->matches, scanner->string_address,
                scanner->mapping, scanner->buffer) != 0) {
            scanner->error = errno == EOVERFLOW ? EOVERFLOW : ENOMEM;
            return -1;
        }
    }
    scanner_reset_string(scanner);
    return 0;
}

static void scanner_append(string_scanner_t *scanner, const unsigned char *bytes,
    size_t byte_count, uintptr_t address)
{
    if (scanner->chars == 0 && !scanner->overflow) scanner->string_address = address;
    if (scanner->overflow) return;
    if (scanner->chars >= scanner->max_chars ||
        byte_count > scanner->capacity - 1U - scanner->length) {
        scanner->overflow = true;
        scanner->length = 0;
        scanner->chars = 0;
        scanner->string_address = 0;
        return;
    }
    memcpy(scanner->buffer + scanner->length, bytes, byte_count);
    scanner->length += byte_count;
    scanner->chars++;
}

static int scanner_feed_ascii(string_scanner_t *scanner, unsigned char byte, uintptr_t address)
{
    if (byte >= 0x20U && byte <= 0x7eU) {
        scanner_append(scanner, &byte, 1U, address);
        return 0;
    }
    return scanner_finish_string(scanner);
}

static int scanner_feed_utf8(string_scanner_t *scanner, unsigned char byte, uintptr_t address)
{
    bool reprocess = true;
    while (reprocess) {
        reprocess = false;
        if (scanner->utf8_expected == 0) {
            if (byte < 0x80U) {
                if (byte >= 0x20U && byte <= 0x7eU) scanner_append(scanner, &byte, 1U, address);
                else if (scanner_finish_string(scanner) != 0) return -1;
            } else if (byte >= 0xc2U && byte <= 0xdfU) {
                scanner->utf8_sequence[0] = byte;
                scanner->utf8_length = 1U;
                scanner->utf8_expected = 1U;
                scanner->utf8_codepoint = byte & 0x1fU;
                scanner->utf8_minimum = UINT32_C(0x80);
                scanner->utf8_address = address;
            } else if (byte >= 0xe0U && byte <= 0xefU) {
                scanner->utf8_sequence[0] = byte;
                scanner->utf8_length = 1U;
                scanner->utf8_expected = 2U;
                scanner->utf8_codepoint = byte & 0x0fU;
                scanner->utf8_minimum = UINT32_C(0x800);
                scanner->utf8_address = address;
            } else if (byte >= 0xf0U && byte <= 0xf4U) {
                scanner->utf8_sequence[0] = byte;
                scanner->utf8_length = 1U;
                scanner->utf8_expected = 3U;
                scanner->utf8_codepoint = byte & 0x07U;
                scanner->utf8_minimum = UINT32_C(0x10000);
                scanner->utf8_address = address;
            } else if (scanner_finish_string(scanner) != 0) return -1;
        } else if ((byte & 0xc0U) == 0x80U) {
            scanner->utf8_sequence[scanner->utf8_length++] = byte;
            scanner->utf8_codepoint = (scanner->utf8_codepoint << 6U) | (byte & 0x3fU);
            scanner->utf8_expected--;
            if (scanner->utf8_expected == 0) {
                if (scanner->utf8_codepoint >= scanner->utf8_minimum &&
                    unicode_printable(scanner->utf8_codepoint)) {
                    scanner_append(scanner, scanner->utf8_sequence,
                        scanner->utf8_length, scanner->utf8_address);
                } else if (scanner_finish_string(scanner) != 0) return -1;
                scanner->utf8_length = 0;
                scanner->utf8_codepoint = 0;
            }
        } else {
            scanner->utf8_expected = 0;
            scanner->utf8_length = 0;
            scanner->utf8_codepoint = 0;
            if (scanner_finish_string(scanner) != 0) return -1;
            reprocess = true;
        }
    }
    return 0;
}

static size_t encode_utf8(uint32_t codepoint, unsigned char output[4])
{
    if (codepoint <= UINT32_C(0x7f)) {
        output[0] = (unsigned char)codepoint;
        return 1U;
    }
    if (codepoint <= UINT32_C(0x7ff)) {
        output[0] = (unsigned char)(0xc0U | (codepoint >> 6U));
        output[1] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        return 2U;
    }
    if (codepoint <= UINT32_C(0xffff)) {
        output[0] = (unsigned char)(0xe0U | (codepoint >> 12U));
        output[1] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        output[2] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        return 3U;
    }
    output[0] = (unsigned char)(0xf0U | (codepoint >> 18U));
    output[1] = (unsigned char)(0x80U | ((codepoint >> 12U) & 0x3fU));
    output[2] = (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
    output[3] = (unsigned char)(0x80U | (codepoint & 0x3fU));
    return 4U;
}

static int scanner_process_utf16_unit(string_scanner_t *scanner, uint16_t unit,
    uintptr_t address)
{
    unsigned char encoded[4];
    uint32_t codepoint;
    size_t encoded_length;
    if (scanner->utf16_have_high_surrogate) {
        if (unit >= UINT16_C(0xdc00) && unit <= UINT16_C(0xdfff)) {
            codepoint = UINT32_C(0x10000) +
                (((uint32_t)scanner->utf16_high_surrogate - UINT32_C(0xd800)) << 10U) +
                ((uint32_t)unit - UINT32_C(0xdc00));
            encoded_length = encode_utf8(codepoint, encoded);
            scanner_append(scanner, encoded, encoded_length, scanner->utf16_high_address);
            scanner->utf16_have_high_surrogate = false;
            return 0;
        }
        scanner->utf16_have_high_surrogate = false;
        if (scanner_finish_string(scanner) != 0) return -1;
    }
    if (unit >= UINT16_C(0xd800) && unit <= UINT16_C(0xdbff)) {
        scanner->utf16_have_high_surrogate = true;
        scanner->utf16_high_surrogate = unit;
        scanner->utf16_high_address = address;
        return 0;
    }
    if (unit >= UINT16_C(0xdc00) && unit <= UINT16_C(0xdfff)) {
        return scanner_finish_string(scanner);
    }
    codepoint = unit;
    if (!unicode_printable(codepoint)) return scanner_finish_string(scanner);
    encoded_length = encode_utf8(codepoint, encoded);
    scanner_append(scanner, encoded, encoded_length, address);
    return 0;
}

static int scanner_feed_utf16le(string_scanner_t *scanner, unsigned char byte,
    uintptr_t address)
{
    uint16_t unit;
    if (!scanner->utf16_have_byte) {
        if ((unsigned int)(address & (uintptr_t)1U) != scanner->utf16_alignment) {
            return 0;
        }
        scanner->utf16_first_byte = byte;
        scanner->utf16_unit_address = address;
        scanner->utf16_have_byte = true;
        return 0;
    }
    if (address != scanner->utf16_unit_address + (uintptr_t)1U) {
        scanner->utf16_have_byte = false;
        return scanner_feed_utf16le(scanner, byte, address);
    }
    unit = (uint16_t)((uint16_t)scanner->utf16_first_byte |
        (uint16_t)((uint16_t)byte << 8U));
    scanner->utf16_have_byte = false;
    return scanner_process_utf16_unit(scanner, unit, scanner->utf16_unit_address);
}

static int scanner_feed(string_scanner_t *scanner, const unsigned char *bytes,
    size_t length, uintptr_t address)
{
    size_t i;
    int result;
    for (i = 0; i < length; ++i) {
        if ((i % STOP_CHECK_GRANULARITY) == 0U) {
            if (stop_requested) {
                scanner->error = ECANCELED;
                return -1;
            }
        }
        if (scanner->encoding == ENCODING_ASCII)
            result = scanner_feed_ascii(scanner, bytes[i], address + i);
        else if (scanner->encoding == ENCODING_UTF8)
            result = scanner_feed_utf8(scanner, bytes[i], address + i);
        else
            result = scanner_feed_utf16le(scanner, bytes[i], address + i);
        if (result != 0) return -1;
    }
    return 0;
}

static int scanner_boundary(string_scanner_t *scanner)
{
    scanner->utf8_expected = 0;
    scanner->utf8_length = 0;
    scanner->utf8_codepoint = 0;
    scanner->utf16_have_byte = false;
    scanner->utf16_have_high_surrogate = false;
    return scanner_finish_string(scanner);
}

static void scanner_destroy(string_scanner_t *scanner)
{
    free(scanner->buffer);
}

static void scan_stats_destroy(scan_stats_t *stats)
{
    free(stats->next_mapping);
    stats->next_mapping = NULL;
}

static int scan_stats_set_next(scan_stats_t *stats, uintptr_t address,
    const char *mapping)
{
    char *copy = strdup(mapping);
    if (copy == NULL) return -1;
    free(stats->next_mapping);
    stats->next_mapping = copy;
    stats->next_address = address;
    stats->has_next_address = true;
    return 0;
}

static void scan_cursor_clear(scan_cursor_t *cursor)
{
    if (cursor->has_scanner) scanner_destroy(&cursor->scanner);
    if (cursor->has_alternate_scanner) scanner_destroy(&cursor->alternate_scanner);
    free(cursor->mapping_name);
    memset(cursor, 0, sizeof(*cursor));
}

static bool scan_cursor_matches_mapping(const scan_cursor_t *cursor,
    const memory_mapping_t *mapping)
{
    return cursor->active && cursor->next_address >= mapping->start &&
        cursor->next_address < mapping->end &&
        cursor->mapping_start == mapping->start &&
        cursor->mapping_end == mapping->end &&
        cursor->file_offset == mapping->file_offset &&
        cursor->device_major == mapping->device_major &&
        cursor->device_minor == mapping->device_minor &&
        cursor->inode == mapping->inode &&
        strcmp(cursor->permissions, mapping->permissions) == 0 &&
        cursor->mapping_name != NULL && strcmp(cursor->mapping_name, mapping->name) == 0;
}

static int scan_cursor_store(scan_cursor_t *cursor, const memory_mapping_t *mapping,
    uintptr_t next_address, string_scanner_t *scanner,
    string_scanner_t *alternate_scanner)
{
    char *mapping_name = strdup(mapping->name);
    if (mapping_name == NULL) return -1;
    scan_cursor_clear(cursor);
    cursor->active = true;
    cursor->next_address = next_address;
    cursor->mapping_start = mapping->start;
    cursor->mapping_end = mapping->end;
    cursor->file_offset = mapping->file_offset;
    cursor->device_major = mapping->device_major;
    cursor->device_minor = mapping->device_minor;
    cursor->inode = mapping->inode;
    (void)memcpy(cursor->permissions, mapping->permissions,
        sizeof(cursor->permissions));
    cursor->mapping_name = mapping_name;
    cursor->scanner = *scanner;
    memset(scanner, 0, sizeof(*scanner));
    cursor->scanner.mapping = cursor->mapping_name;
    cursor->has_scanner = true;
    if (alternate_scanner != NULL) {
        cursor->alternate_scanner = *alternate_scanner;
        memset(alternate_scanner, 0, sizeof(*alternate_scanner));
        cursor->alternate_scanner.mapping = cursor->mapping_name;
        cursor->has_alternate_scanner = true;
    }
    return 0;
}

static bool scan_cursor_take(scan_cursor_t *cursor, const memory_mapping_t *mapping,
    matcher_t *matcher, match_collection_t *matches, string_scanner_t *scanner,
    string_scanner_t *alternate_scanner)
{
    char *mapping_name;
    bool needs_alternate = alternate_scanner != NULL;
    if (!scan_cursor_matches_mapping(cursor, mapping) || !cursor->has_scanner ||
        cursor->has_alternate_scanner != needs_alternate) return false;
    mapping_name = cursor->mapping_name;
    *scanner = cursor->scanner;
    scanner->mapping = mapping->name;
    scanner->matcher = matcher;
    scanner->matches = matches;
    if (needs_alternate) {
        *alternate_scanner = cursor->alternate_scanner;
        alternate_scanner->mapping = mapping->name;
        alternate_scanner->matcher = matcher;
        alternate_scanner->matches = matches;
    }
    memset(cursor, 0, sizeof(*cursor));
    free(mapping_name);
    return true;
}

static uint64_t timespec_to_ns(const struct timespec *value)
{
    return (uint64_t)value->tv_sec * UINT64_C(1000000000) + (uint64_t)value->tv_nsec;
}

static bool scan_timed_out(uint64_t started_ns, uint64_t timeout_ns)
{
    struct timespec now;
    if (timeout_ns == 0) return false;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return false;
    return timespec_to_ns(&now) - started_ns >= timeout_ns;
}

static size_t bytes_to_page_boundary(uintptr_t address, size_t page_size)
{
    size_t offset = (size_t)(address % page_size);
    return offset == 0 ? page_size : page_size - offset;
}

static void log_skipped_range(const options_t *options, const string_scanner_t *scanner,
    uintptr_t start, uintmax_t length)
{
    uintptr_t end;
    if (length == 0) return;
    end = length > (uintmax_t)(UINTPTR_MAX - start) ? UINTPTR_MAX :
        start + (uintptr_t)length;
    log_message(options, 2,
        "%s: warning: cannot read PID %d at 0x%" PRIxPTR "-0x%" PRIxPTR
        " in mapping '%s'; skipping %" PRIuMAX " bytes",
        PROGRAM_NAME, options->pid, start, end, scanner->mapping, length);
}

static region_result_t read_region(const options_t *options, uintptr_t start,
    uintptr_t end, size_t page_size, unsigned char *buffer, struct iovec *remote,
    size_t remote_capacity, string_scanner_t *scanner,
    string_scanner_t *alternate_scanner, scan_stats_t *stats,
    uint64_t scan_started_ns, bool *partial, uintptr_t *next_address)
{
    uintptr_t address = start;
    uintptr_t fault_start = 0;
    uintmax_t fault_bytes = 0;
    *next_address = start;
    while (address < end) {
        struct iovec local;
        uintptr_t cursor = address;
        size_t total = 0;
        size_t count = 0;
        size_t chunk_limit = READ_CHUNK_SIZE;
        ssize_t bytes_read;
        if (stop_requested) {
            log_skipped_range(options, scanner, fault_start, fault_bytes);
            return REGION_STOPPED;
        }
        if (scan_timed_out(scan_started_ns, options->scan_timeout_ns)) {
            log_skipped_range(options, scanner, fault_start, fault_bytes);
            return REGION_TIMEOUT;
        }
        if (stats->bytes_read >= options->max_scan_size) {
            log_skipped_range(options, scanner, fault_start, fault_bytes);
            return REGION_LIMIT;
        }
        if (options->max_scan_size - stats->bytes_read < (uint64_t)chunk_limit)
            chunk_limit = (size_t)(options->max_scan_size - stats->bytes_read);
        while (cursor < end && total < chunk_limit && count < remote_capacity) {
            uintmax_t remaining_region = (uintmax_t)(end - cursor);
            size_t length = bytes_to_page_boundary(cursor, page_size);
            size_t remaining_chunk = chunk_limit - total;
            if ((uintmax_t)length > remaining_region) length = (size_t)remaining_region;
            if (length > remaining_chunk) length = remaining_chunk;
            remote[count].iov_base = (void *)cursor;
            remote[count].iov_len = length;
            count++;
            cursor += length;
            total += length;
        }
        local.iov_base = buffer;
        local.iov_len = total;
        errno = 0;
        bytes_read = process_vm_readv(options->pid, &local, 1, remote,
            (unsigned long)count, 0);
        if (bytes_read > 0) {
            log_skipped_range(options, scanner, fault_start, fault_bytes);
            fault_bytes = 0;
            if ((size_t)bytes_read > total) {
                errno = EIO;
                return REGION_FATAL;
            }
            if (scanner_feed(scanner, buffer, (size_t)bytes_read, address) != 0) {
                if (scanner->error == ETIMEDOUT) return REGION_TIMEOUT;
                if (scanner->error == ECANCELED) return REGION_STOPPED;
                if (scanner->error == EOVERFLOW) return REGION_RESULT_LIMIT;
                return REGION_FATAL;
            }
            if (alternate_scanner != NULL &&
                scanner_feed(alternate_scanner, buffer, (size_t)bytes_read, address) != 0) {
                if (alternate_scanner->error == ETIMEDOUT) return REGION_TIMEOUT;
                if (alternate_scanner->error == ECANCELED) return REGION_STOPPED;
                if (alternate_scanner->error == EOVERFLOW) return REGION_RESULT_LIMIT;
                return REGION_FATAL;
            }
            address += (uintptr_t)bytes_read;
            stats->bytes_read += (uint64_t)bytes_read;
            *next_address = address;
            continue;
        }
        if (bytes_read == 0) {
            errno = EIO;
            return REGION_FATAL;
        }
        if (errno == EINTR) {
            if (stop_requested) return REGION_STOPPED;
            continue;
        }
        if (errno == ESRCH) return REGION_TARGET_GONE;
        if (errno == EPERM || errno == EACCES) return REGION_PERMISSION_DENIED;
        if (errno == EFAULT) {
            size_t skip = bytes_to_page_boundary(address, page_size);
            uintmax_t remaining = (uintmax_t)(end - address);
            if (!options->best_effort) return REGION_PAGE_FAULT;
            if ((uintmax_t)skip > remaining) skip = (size_t)remaining;
            if (scanner_boundary(scanner) != 0 ||
                (alternate_scanner != NULL && scanner_boundary(alternate_scanner) != 0))
                return REGION_FATAL;
            if (fault_bytes == 0) fault_start = address;
            fault_bytes += (uintmax_t)skip;
            address += skip;
            *next_address = address;
            stats->skipped_pages++;
            *partial = true;
            continue;
        }
        log_skipped_range(options, scanner, fault_start, fault_bytes);
        return REGION_FATAL;
    }
    log_skipped_range(options, scanner, fault_start, fault_bytes);
    if (scanner_boundary(scanner) != 0 ||
        (alternate_scanner != NULL && scanner_boundary(alternate_scanner) != 0))
        return REGION_FATAL;
    *next_address = end;
    return REGION_OK;
}

static int mapping_selected(const regex_list_t *includes, const regex_list_t *excludes,
    const char *mapping, bool *selected)
{
    bool matched;
    *selected = false;
    if (strcmp(mapping, "[vvar]") == 0 ||
        strcmp(mapping, "[vvar_vclock]") == 0 ||
        strcmp(mapping, "[vsyscall]") == 0) {
        return 0;
    }
    if (excludes->count > 0) {
        if (regex_list_any(excludes, mapping, &matched) != 0) return -1;
        if (matched) return 0;
    }
    if (includes->count == 0) {
        *selected = true;
        return 0;
    }
    if (regex_list_any(includes, mapping, &matched) != 0) return -1;
    *selected = matched;
    return 0;
}

static int parse_maps_line(char *line, memory_mapping_t *mapping)
{
    uintmax_t parsed_start, parsed_end;
    int pathname_offset = 0;
    int fields;
    char *name;
    size_t length;
    memset(mapping, 0, sizeof(*mapping));
    fields = sscanf(line, "%jx-%jx %4s %jx %x:%x %ju %n",
        &parsed_start, &parsed_end, mapping->permissions, &mapping->file_offset,
        &mapping->device_major, &mapping->device_minor, &mapping->inode,
        &pathname_offset);
    if (fields != 7 || pathname_offset <= 0 || parsed_start > UINTPTR_MAX ||
        parsed_end > UINTPTR_MAX || parsed_start >= parsed_end) return -1;
    name = line + pathname_offset;
    while (*name == ' ' || *name == '\t') name++;
    length = strlen(name);
    while (length > 0 && (name[length - 1U] == '\n' || name[length - 1U] == '\r'))
        name[--length] = '\0';
    if (*name == '\0') name = (char *)"[anonymous]";
    mapping->start = (uintptr_t)parsed_start;
    mapping->end = (uintptr_t)parsed_end;
    mapping->name = name;
    return 0;
}

static int target_maps_file(pid_t pid, const struct stat *file_status, bool *mapped)
{
    char path[64];
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0;
    int result = 0;
    *mapped = false;
    (void)snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    stream = fopen(path, "r");
    if (stream == NULL) return -1;
    while (getline(&line, &capacity, stream) >= 0) {
        memory_mapping_t mapping;
        if (parse_maps_line(line, &mapping) != 0) continue;
        if (mapping.inode == (uintmax_t)file_status->st_ino &&
            mapping.device_major == major(file_status->st_dev) &&
            mapping.device_minor == minor(file_status->st_dev)) {
            *mapped = true;
            break;
        }
    }
    if (ferror(stream)) result = -1;
    free(line);
    if (fclose(stream) != 0 && result == 0) result = -1;
    return result;
}

static bool mapping_status_matches(const memory_mapping_t *mapping,
    const struct stat *status)
{
    return S_ISREG(status->st_mode) && status->st_size >= 0 &&
        (uintmax_t)major(status->st_dev) == (uintmax_t)mapping->device_major &&
        (uintmax_t)minor(status->st_dev) == (uintmax_t)mapping->device_minor &&
        (uintmax_t)status->st_ino == mapping->inode;
}

static bool mapping_file_size_from_path(const char *path, int flags,
    const memory_mapping_t *mapping, uintmax_t *file_size)
{
    int descriptor = open(path, O_PATH | O_CLOEXEC | flags);
    struct stat status;
    bool matched = false;
    if (descriptor < 0) return false;
    if (fstat(descriptor, &status) == 0 && mapping_status_matches(mapping, &status)) {
        *file_size = (uintmax_t)status.st_size;
        matched = true;
    }
    (void)close(descriptor);
    return matched;
}

static bool mapping_file_size(pid_t pid, const memory_mapping_t *mapping,
    uintmax_t *file_size)
{
    char map_file_path[128];
    char *root_path = NULL;
    int length;
    bool found;
    if (mapping->inode == 0) return false;
    length = snprintf(map_file_path, sizeof(map_file_path),
        "/proc/%d/map_files/%" PRIxPTR "-%" PRIxPTR,
        pid, mapping->start, mapping->end);
    if (length > 0 && (size_t)length < sizeof(map_file_path) &&
        mapping_file_size_from_path(map_file_path, 0, mapping, file_size)) {
        return true;
    }
    if (mapping->name[0] != '/') return false;
    if (asprintf(&root_path, "/proc/%d/root%s", pid, mapping->name) < 0) return false;
    found = mapping_file_size_from_path(root_path, O_NOFOLLOW, mapping, file_size);
    free(root_path);
    return found;
}

static uintptr_t mapping_backed_end(pid_t pid, const memory_mapping_t *mapping,
    size_t page_size, bool *limited)
{
    uintmax_t file_size;
    uintmax_t available;
    uintmax_t rounded;
    uintmax_t mapping_size = (uintmax_t)(mapping->end - mapping->start);
    uintmax_t page_mask = (uintmax_t)page_size - 1U;

    *limited = false;
    if (!mapping_file_size(pid, mapping, &file_size)) return mapping->end;
    available = file_size > mapping->file_offset ? file_size - mapping->file_offset : 0U;
    if (available == 0) {
        rounded = 0;
    } else if (available > UINTMAX_MAX - page_mask) {
        rounded = UINTMAX_MAX;
    } else {
        rounded = ((available + page_mask) / (uintmax_t)page_size) * (uintmax_t)page_size;
    }
    if (rounded >= mapping_size) return mapping->end;
    *limited = true;
    return mapping->start + (uintptr_t)rounded;
}

static scan_result_t scan_process(const options_t *options, matcher_t *matcher,
    const regex_list_t *includes, const regex_list_t *excludes,
    match_collection_t *matches, size_t page_size, scan_stats_t *stats,
    scan_cursor_t *cursor)
{
    char maps_path[64];
    FILE *maps;
    char *line = NULL;
    size_t line_capacity = 0;
    unsigned char *buffer = NULL;
    struct iovec *remote = NULL;
    size_t remote_capacity = READ_CHUNK_SIZE / page_size + 2U;
    struct timespec started;
    uint64_t started_ns;
    bool partial = false;
    bool can_continue = options->interval_set &&
        options->scan_strategy == SCAN_STRATEGY_CONTINUE;
    bool seeking = can_continue && cursor->active;
    uintptr_t resume_address = seeking ? cursor->next_address : 0;
    scan_result_t result = SCAN_COMPLETE;
    (void)snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", options->pid);
    maps = fopen(maps_path, "r");
    if (maps == NULL) {
        if (errno == ENOENT || errno == ESRCH) return SCAN_TARGET_EXITED;
        if (errno == EACCES || errno == EPERM) return SCAN_PERMISSION_DENIED;
        perror("fopen /proc/PID/maps");
        return SCAN_FATAL;
    }
    buffer = malloc(READ_CHUNK_SIZE);
    remote = calloc(remote_capacity, sizeof(*remote));
    if (buffer == NULL || remote == NULL || clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        perror("scan initialization");
        result = SCAN_FATAL;
        goto cleanup;
    }
    started_ns = timespec_to_ns(&started);
    while (getline(&line, &line_capacity, maps) >= 0) {
        memory_mapping_t mapping;
        uintptr_t scan_start;
        uintptr_t scan_end;
        uintptr_t next_address;
        bool limited;
        bool selected;
        bool resumed = false;
        string_scanner_t scanner;
        string_scanner_t alternate_scanner;
        string_scanner_t *alternate = NULL;
        region_result_t region_result;
        if (stop_requested) {
            result = SCAN_STOPPED;
            goto cleanup;
        }
        if (parse_maps_line(line, &mapping) != 0) {
            log_message(options, 1, "%s: warning: malformed maps entry ignored", PROGRAM_NAME);
            partial = true;
            continue;
        }
        if (mapping.permissions[0] != 'r') continue;
        if (mapping_selected(includes, excludes, mapping.name, &selected) != 0) {
            perror("match mapping name");
            result = SCAN_FATAL;
            goto cleanup;
        }
        if (!selected) continue;
        scan_end = mapping_backed_end(options->pid, &mapping, page_size, &limited);
        if (limited) {
            uintmax_t mapped_bytes = (uintmax_t)(mapping.end - mapping.start);
            uintmax_t backed_bytes = (uintmax_t)(scan_end - mapping.start);
            uintmax_t skipped_bytes = mapped_bytes - backed_bytes;
            uint64_t room = UINT64_MAX - stats->unbacked_file_bytes;
            stats->unbacked_file_bytes = skipped_bytes > (uintmax_t)room ?
                UINT64_MAX : stats->unbacked_file_bytes + (uint64_t)skipped_bytes;
            if (stats->limited_file_mappings != UINT64_MAX) stats->limited_file_mappings++;
            log_message(options, 2,
                "%s: file mapping '%s': scanning %" PRIuMAX " of %" PRIuMAX
                " bytes; skipped %" PRIuMAX " bytes beyond EOF",
                PROGRAM_NAME, mapping.name, backed_bytes, mapped_bytes, skipped_bytes);
            if (scan_end == mapping.start) continue;
        }
        scan_start = mapping.start;
        if (seeking) {
            if (scan_end <= resume_address) continue;
            if (resume_address > scan_start) scan_start = resume_address;
            if (options->encoding == ENCODING_UTF16LE) alternate = &alternate_scanner;
            if (scan_cursor_matches_mapping(cursor, &mapping) &&
                cursor->next_address == scan_start) {
                resumed = scan_cursor_take(cursor, &mapping, matcher, matches,
                    &scanner, alternate);
            }
            if (!resumed) {
                log_message(options, 1,
                    "%s: warning: mapping at continuation address 0x%" PRIxPTR
                    " changed; restarting at 0x%" PRIxPTR " in mapping '%s'",
                    PROGRAM_NAME, resume_address, mapping.start, mapping.name);
                partial = true;
                scan_start = mapping.start;
                scan_cursor_clear(cursor);
            }
            seeking = false;
        }
        if (!resumed &&
            scanner_init(&scanner, options, mapping.name, matcher, matches) != 0) {
            perror("malloc string scanner");
            result = SCAN_FATAL;
            goto cleanup;
        }
        if (options->encoding == ENCODING_UTF16LE && !resumed) {
            alternate = &alternate_scanner;
            if (scanner_init(&alternate_scanner, options, mapping.name, matcher,
                    matches) != 0) {
                perror("malloc alternate string scanner");
                scanner_destroy(&scanner);
                result = SCAN_FATAL;
                goto cleanup;
            }
            alternate_scanner.utf16_alignment = 1U;
        }
        region_result = read_region(options, scan_start, scan_end, page_size, buffer, remote,
            remote_capacity, &scanner, alternate, stats, started_ns, &partial,
            &next_address);
        if (region_result == REGION_OK) {
            if (alternate != NULL) scanner_destroy(alternate);
            scanner_destroy(&scanner);
            stats->mappings_read++;
            continue;
        }
        if ((region_result == REGION_LIMIT || region_result == REGION_TIMEOUT) &&
            can_continue) {
            if (scan_stats_set_next(stats, next_address, mapping.name) != 0 ||
                scan_cursor_store(cursor, &mapping, next_address, &scanner, alternate) != 0) {
                perror("save scan continuation");
                result = SCAN_FATAL;
            } else {
                const char *reason = region_result == REGION_LIMIT ?
                    "scan byte limit reached" : "scan timed out";
                log_message(options, 1,
                    "%s: %s; next scan continues at 0x%" PRIxPTR
                    " in mapping '%s'",
                    PROGRAM_NAME, reason, next_address, mapping.name);
                result = SCAN_MORE;
            }
            if (alternate != NULL) scanner_destroy(alternate);
            scanner_destroy(&scanner);
            goto cleanup;
        }
        if (scan_stats_set_next(stats, next_address, mapping.name) != 0) {
            perror("save next scan address");
            result = SCAN_FATAL;
        } else if (region_result == REGION_STOPPED) result = SCAN_STOPPED;
        else if (region_result == REGION_TARGET_GONE) result = SCAN_TARGET_EXITED;
        else if (region_result == REGION_PERMISSION_DENIED) result = SCAN_PERMISSION_DENIED;
        else if (region_result == REGION_TIMEOUT) {
            (void)fprintf(stderr, "%s: scan timed out\n", PROGRAM_NAME);
            result = SCAN_PARTIAL;
        } else if (region_result == REGION_PAGE_FAULT) {
            (void)fprintf(stderr,
                "%s: remote memory changed or became inaccessible; use --best-effort to continue\n",
                PROGRAM_NAME);
            result = SCAN_PARTIAL;
        } else if (region_result == REGION_LIMIT) {
            log_message(options, 1,
                "%s: scan byte limit reached (%" PRIu64 " bytes)",
                PROGRAM_NAME, options->max_scan_size);
            result = SCAN_PARTIAL;
        } else if (region_result == REGION_RESULT_LIMIT) {
            log_message(options, 1, "%s: result limit reached (%zu)",
                PROGRAM_NAME, options->max_results);
            result = SCAN_PARTIAL;
        } else {
            int scan_error = scanner.error != 0 ? scanner.error :
                (alternate != NULL ? alternate->error : 0);
            if (scan_error != 0 && scan_error != EOVERFLOW) {
                errno = scan_error;
                perror("scan strings");
            } else if (scan_error == 0) {
                perror("process_vm_readv");
            }
            result = SCAN_FATAL;
        }
        if (alternate != NULL) scanner_destroy(alternate);
        scanner_destroy(&scanner);
        goto cleanup;
    }
    if (ferror(maps)) {
        perror("read /proc/PID/maps");
        result = SCAN_FATAL;
    } else {
        if (seeking) {
            log_message(options, 1,
                "%s: warning: mapping at continuation address 0x%" PRIxPTR
                " disappeared before the next scan",
                PROGRAM_NAME, resume_address);
            partial = true;
        }
        stats->reached_end = true;
        scan_cursor_clear(cursor);
        if (partial) {
            log_message(options, 1,
                "%s: warning: scan completed with skipped pages=%" PRIu64,
                PROGRAM_NAME, stats->skipped_pages);
            result = SCAN_PARTIAL;
        }
    }
cleanup:
    stats->incomplete = stats->incomplete || partial || result == SCAN_PARTIAL;
    free(remote);
    free(buffer);
    free(line);
    (void)fclose(maps);
    return result;
}

static int read_process_starttime(pid_t pid, uint64_t *starttime)
{
    char path[64];
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0;
    char *cursor, *end;
    int field = 3;
    int result = -1;
    (void)snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    stream = fopen(path, "r");
    if (stream == NULL) return -1;
    if (getline(&line, &capacity, stream) < 0) goto cleanup;
    cursor = strrchr(line, ')');
    if (cursor == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    cursor++;
    while (field <= 22) {
        while (*cursor == ' ') cursor++;
        if (*cursor == '\0' || *cursor == '\n') {
            errno = EINVAL;
            goto cleanup;
        }
        end = cursor;
        while (*end != '\0' && *end != '\n' && *end != ' ') end++;
        if (field == 22) {
            char saved = *end;
            uint64_t parsed;
            *end = '\0';
            if (!parse_unsigned(cursor, &parsed)) {
                *end = saved;
                errno = EINVAL;
                goto cleanup;
            }
            *end = saved;
            *starttime = parsed;
            result = 0;
            goto cleanup;
        }
        cursor = end;
        field++;
    }
cleanup:
    free(line);
    (void)fclose(stream);
    return result;
}

static int output_open(output_t *output, const options_t *options)
{
    int descriptor;
    int flags;
    struct stat status;
    struct stat path_status = { 0 };
    bool target_mapping = false;
    memset(output, 0, sizeof(*output));
    output->format = options->output_format;
    output->max_bytes = options->max_output_size;
    output->min_free_bytes = options->min_free_space;
    if (strcmp(options->output_path, "-") == 0) {
        output->stream = stdout;
        if (fstat(fileno(stdout), &status) != 0) return -1;
        if (!S_ISFIFO(status.st_mode) && !S_ISSOCK(status.st_mode) &&
            isatty(fileno(stdout)) != 1) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }
    if (options->append_output) {
        if (lstat(options->output_path, &path_status) != 0) return -1;
        if (!S_ISREG(path_status.st_mode) || path_status.st_nlink != 1) {
            errno = EINVAL;
            return -1;
        }
    }
    flags = O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (options->append_output) flags |= O_APPEND;
    else flags |= O_CREAT | O_EXCL;
    descriptor = open(options->output_path, flags, S_IRUSR | S_IWUSR);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &status) != 0) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1) {
        (void)close(descriptor);
        errno = EINVAL;
        return -1;
    }
    if (options->append_output &&
        (path_status.st_dev != status.st_dev || path_status.st_ino != status.st_ino)) {
        (void)close(descriptor);
        errno = EAGAIN;
        return -1;
    }
    if (status.st_uid != geteuid() || (status.st_mode & 07777U) != 0600U) {
        (void)close(descriptor);
        errno = EACCES;
        return -1;
    }
    if (status.st_size < 0 || (uintmax_t)status.st_size > UINT64_MAX) {
        (void)close(descriptor);
        errno = EOVERFLOW;
        return -1;
    }
    if (target_maps_file(options->pid, &status, &target_mapping) != 0 || target_mapping) {
        int saved_errno = target_mapping ? EBUSY : errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    output->bytes_written = (uint64_t)status.st_size;
    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    output->stream = fdopen(descriptor, "a");
    if (output->stream == NULL) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    output->must_close = true;
    output->sync_file = true;
    return 0;
}

static bool filesystem_has_room(int descriptor, uint64_t bytes, uint64_t reserve)
{
    struct statvfs status;
    uint64_t available;
    uint64_t blocks;
    uint64_t block_size;
    if (fstatvfs(descriptor, &status) != 0) return false;
    blocks = (uint64_t)status.f_bavail;
    block_size = (uint64_t)status.f_frsize;
    available = block_size != 0 && blocks > UINT64_MAX / block_size ?
        UINT64_MAX : blocks * block_size;
    if (bytes > UINT64_MAX - reserve || available < bytes + reserve) {
        errno = ENOSPC;
        return false;
    }
    return true;
}

static int output_json_string(FILE *stream, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;
    if (fputc('"', stream) == EOF) return -1;
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"': if (fputs("\\\"", stream) == EOF) return -1; break;
        case '\\': if (fputs("\\\\", stream) == EOF) return -1; break;
        case '\b': if (fputs("\\b", stream) == EOF) return -1; break;
        case '\f': if (fputs("\\f", stream) == EOF) return -1; break;
        case '\n': if (fputs("\\n", stream) == EOF) return -1; break;
        case '\r': if (fputs("\\r", stream) == EOF) return -1; break;
        case '\t': if (fputs("\\t", stream) == EOF) return -1; break;
        default:
            if (*cursor < 0x20U) {
                if (fprintf(stream, "\\u%04x", (unsigned int)*cursor) < 0) return -1;
            } else if (fputc(*cursor, stream) == EOF) return -1;
            break;
        }
        cursor++;
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int output_tsv_string(FILE *stream, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != '\0') {
        if (*cursor == '\\') { if (fputs("\\\\", stream) == EOF) return -1; }
        else if (*cursor == '\t') { if (fputs("\\t", stream) == EOF) return -1; }
        else if (*cursor == '\n') { if (fputs("\\n", stream) == EOF) return -1; }
        else if (*cursor == '\r') { if (fputs("\\r", stream) == EOF) return -1; }
        else if (fputc(*cursor, stream) == EOF) return -1;
        cursor++;
    }
    return 0;
}

static int format_timestamp(char output[32])
{
    struct timespec now;
    struct tm broken_down;
    size_t length;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0 ||
        gmtime_r(&now.tv_sec, &broken_down) == NULL) return -1;
    length = strftime(output, 32, "%Y-%m-%dT%H:%M:%S", &broken_down);
    if (length == 0 || length + 5U >= 32U) {
        errno = EOVERFLOW;
        return -1;
    }
    (void)snprintf(output + length, 32U - length, ".%03ldZ", now.tv_nsec / 1000000L);
    return 0;
}

static int output_match_to_stream(FILE *stream, output_format_t format,
    const options_t *options,
    const match_t *match, const char *event, uint64_t scan_number,
    uint64_t cycle_number, bool complete, const char *timestamp)
{
    if (format == FORMAT_TEXT) {
        if (options->emit_mode == EMIT_CHANGES && fprintf(stream, "%s\t", event) < 0) return -1;
        return fprintf(stream, "%s\n", match->value) < 0 ? -1 : 0;
    }
    if (format == FORMAT_TSV) {
        if (fprintf(stream, "%s\t%" PRIu64 "\t%s\t%d\t0x%" PRIxPTR "\t",
                timestamp, scan_number, event, options->pid, match->address) < 0 ||
            output_tsv_string(stream, match->mapping) != 0 || fputc('\t', stream) == EOF ||
            output_tsv_string(stream, match->value) != 0 ||
            fprintf(stream, "\t%s\n", complete ? "complete" : "partial") < 0) return -1;
        return 0;
    }
    if (!options->debug_output) {
        if (fputc('{', stream) == EOF) return -1;
        if (options->emit_mode == EMIT_CHANGES) {
            if (fputs("\"event\":", stream) == EOF ||
                output_json_string(stream, event) != 0 ||
                fputc(',', stream) == EOF) return -1;
        }
        if (fputs("\"value\":", stream) == EOF ||
            output_json_string(stream, match->value) != 0 ||
            fputs("}\n", stream) == EOF) return -1;
        return 0;
    }
    if (fprintf(stream, "{\"type\":\"match\",\"timestamp\":") < 0 ||
        output_json_string(stream, timestamp) != 0 ||
        fprintf(stream, ",\"scan\":%" PRIu64 ",\"cycle\":%" PRIu64
            ",\"event\":", scan_number, cycle_number) < 0 ||
        output_json_string(stream, event) != 0 ||
        fprintf(stream, ",\"complete\":%s,\"pid\":%d,\"address\":\"0x%" PRIxPTR
            "\",\"mapping\":", complete ? "true" : "false", options->pid,
            match->address) < 0 ||
        output_json_string(stream, match->mapping) != 0 ||
        fputs(",\"value\":", stream) == EOF ||
        output_json_string(stream, match->value) != 0 || fputs("}\n", stream) == EOF) return -1;
    return 0;
}

static output_write_result_t output_append_record(output_t *output,
    const char *record, size_t length)
{
    uint64_t record_length;
    struct stat status;
    record_length = (uint64_t)length;
    if (output->sync_file) {
        if (fstat(fileno(output->stream), &status) != 0 || status.st_size < 0 ||
            (uintmax_t)status.st_size > UINT64_MAX) return OUTPUT_WRITE_ERROR;
        if ((uint64_t)status.st_size > output->bytes_written)
            output->bytes_written = (uint64_t)status.st_size;
    }
    if (output->max_bytes != 0 &&
        (output->bytes_written >= output->max_bytes ||
            record_length > output->max_bytes - output->bytes_written)) {
        return OUTPUT_WRITE_LIMIT;
    }
    if (output->sync_file &&
        !filesystem_has_room(fileno(output->stream), record_length, output->min_free_bytes)) {
        return OUTPUT_WRITE_ERROR;
    }
    if (length != 0 && fwrite(record, 1U, length, output->stream) != length) {
        return OUTPUT_WRITE_ERROR;
    }
    output->bytes_written += record_length;
    return OUTPUT_WRITE_OK;
}

static output_write_result_t output_match(output_t *output, const options_t *options,
    const match_t *match, const char *event, uint64_t scan_number,
    uint64_t cycle_number, bool complete, const char *timestamp)
{
    char *record = NULL;
    size_t length = 0;
    FILE *memory;
    int format_result;
    int close_result;
    int saved_errno;
    output_write_result_t result;

    if (output->max_bytes == 0) {
        return output_match_to_stream(output->stream, output->format, options, match,
            event, scan_number, cycle_number, complete, timestamp) == 0 ?
            OUTPUT_WRITE_OK : OUTPUT_WRITE_ERROR;
    }
    memory = open_memstream(&record, &length);
    if (memory == NULL) return OUTPUT_WRITE_ERROR;
    format_result = output_match_to_stream(memory, output->format, options, match,
        event, scan_number, cycle_number, complete, timestamp);
    saved_errno = errno;
    close_result = fclose(memory);
    if (format_result != 0 || close_result != 0) {
        free(record);
        if (format_result != 0) errno = saved_errno;
        return OUTPUT_WRITE_ERROR;
    }
    result = output_append_record(output, record, length);
    free(record);
    return result;
}

static int output_scan_summary_to_stream(FILE *stream, const options_t *options,
    uint64_t scan_number, uint64_t cycle_number, bool cycle_finished,
    bool cycle_complete, const scan_stats_t *stats, const char *timestamp)
{
    if (fprintf(stream, "{\"type\":\"scan_summary\",\"timestamp\":") < 0 ||
        output_json_string(stream, timestamp) != 0 ||
        fprintf(stream,
            ",\"scan\":%" PRIu64 ",\"cycle\":%" PRIu64
            ",\"complete\":%s,\"cycle_finished\":%s,\"cycle_complete\":%s,"
            "\"scan_strategy\":",
            scan_number, cycle_number, cycle_complete ? "true" : "false",
            cycle_finished ? "true" : "false", cycle_complete ? "true" : "false") < 0 ||
        output_json_string(stream, scan_strategy_name(options->scan_strategy)) != 0 ||
        fprintf(stream,
            ",\"pid\":%d,"
            "\"bytes_read\":%" PRIu64 ",\"skipped_pages\":%" PRIu64 ","
            "\"mappings_read\":%" PRIu64 ","
            "\"unbacked_file_bytes\":%" PRIu64 ","
            "\"limited_file_mappings\":%" PRIu64 ",\"next_address\":",
            options->pid, stats->bytes_read, stats->skipped_pages,
            stats->mappings_read, stats->unbacked_file_bytes,
            stats->limited_file_mappings) < 0) return -1;
    if (stats->has_next_address) {
        if (fprintf(stream, "\"0x%" PRIxPTR "\"", stats->next_address) < 0) return -1;
    } else if (fputs("null", stream) == EOF) return -1;
    if (fputs(",\"next_mapping\":", stream) == EOF) return -1;
    if (stats->has_next_address) {
        if (output_json_string(stream, stats->next_mapping) != 0) return -1;
    } else if (fputs("null", stream) == EOF) return -1;
    if (fputs("}\n", stream) == EOF) return -1;
    return 0;
}

static output_write_result_t output_scan_summary(output_t *output,
    const options_t *options, uint64_t scan_number, uint64_t cycle_number,
    bool cycle_finished, bool cycle_complete, const scan_stats_t *stats,
    const char *timestamp)
{
    char *record = NULL;
    size_t length = 0;
    FILE *memory;
    int format_result;
    int close_result;
    int saved_errno;
    output_write_result_t result;

    if (output->format != FORMAT_JSONL) return OUTPUT_WRITE_OK;
    if (output->max_bytes == 0) {
        return output_scan_summary_to_stream(output->stream, options, scan_number,
            cycle_number, cycle_finished, cycle_complete, stats, timestamp) == 0 ?
            OUTPUT_WRITE_OK : OUTPUT_WRITE_ERROR;
    }
    memory = open_memstream(&record, &length);
    if (memory == NULL) return OUTPUT_WRITE_ERROR;
    format_result = output_scan_summary_to_stream(memory, options, scan_number,
        cycle_number, cycle_finished, cycle_complete, stats, timestamp);
    saved_errno = errno;
    close_result = fclose(memory);
    if (format_result != 0 || close_result != 0) {
        free(record);
        if (format_result != 0) errno = saved_errno;
        return OUTPUT_WRITE_ERROR;
    }
    result = output_append_record(output, record, length);
    free(record);
    return result;
}

static bool output_limit_reached(const output_t *output)
{
    return output->max_bytes != 0 && output->bytes_written >= output->max_bytes;
}

static int output_flush(output_t *output)
{
    if (fflush(output->stream) != 0) return -1;
    if (output->sync_file && fsync(fileno(output->stream)) != 0) return -1;
    return 0;
}
static void output_close(output_t *output) { if (output->must_close) (void)fclose(output->stream); }

static int state_write_hex(FILE *stream, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != '\0') {
        if (fprintf(stream, "%02x", (unsigned int)*cursor) < 0) return -1;
        cursor++;
    }
    return 0;
}

static int hex_value(int character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static char *state_decode_hex(const char *text)
{
    size_t length = strlen(text);
    size_t decoded_length;
    char *decoded;
    size_t i;
    if ((length & 1U) != 0) { errno = EINVAL; return NULL; }
    decoded_length = length / 2U;
    if (decoded_length == SIZE_MAX) { errno = EOVERFLOW; return NULL; }
    decoded = malloc(decoded_length + 1U);
    if (decoded == NULL) return NULL;
    for (i = 0; i < decoded_length; ++i) {
        int high = hex_value((unsigned char)text[i * 2U]);
        int low = hex_value((unsigned char)text[i * 2U + 1U]);
        if (high < 0 || low < 0 || (high == 0 && low == 0)) {
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
        decoded[i] = (char)((high << 4) | low);
    }
    decoded[decoded_length] = '\0';
    return decoded;
}

static void trim_line_ending(char *line, size_t *length)
{
    while (*length > 0 &&
        (line[*length - 1U] == '\n' || line[*length - 1U] == '\r')) {
        line[--(*length)] = '\0';
    }
}

static int state_load(const options_t *options, const output_t *output,
    int state_lock, match_set_t *state, bool *state_exists)
{
    FILE *stream;
    int descriptor;
    struct stat status;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t bytes_read;
    uint64_t total_read = 0;
    size_t length;
    char expected[128];
    int result = -1;
    bool target_mapping = false;
    *state_exists = options->state_path == NULL;
    if (options->state_path == NULL) return 0;
    descriptor = open(options->state_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(descriptor, &status) != 0) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_uid != geteuid() || (status.st_mode & 07777U) != 0600U) {
        (void)close(descriptor);
        errno = EACCES;
        return -1;
    }
    if (status.st_size < 0 || (uintmax_t)status.st_size > options->max_state_size) {
        (void)close(descriptor);
        errno = EFBIG;
        return -1;
    }
    if (target_maps_file(options->pid, &status, &target_mapping) != 0 || target_mapping) {
        int saved_errno = target_mapping ? EBUSY : errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if (state_lock >= 0) {
        struct stat lock_status;
        if (fstat(state_lock, &lock_status) != 0) {
            int saved_errno = errno;
            (void)close(descriptor);
            errno = saved_errno;
            return -1;
        }
        if (status.st_dev == lock_status.st_dev && status.st_ino == lock_status.st_ino) {
            (void)close(descriptor);
            errno = EINVAL;
            (void)fprintf(stderr, "%s: state and lock files refer to the same file\n",
                PROGRAM_NAME);
            return -1;
        }
    }
    if (output->sync_file) {
        struct stat output_status;
        if (fstat(fileno(output->stream), &output_status) != 0) {
            int saved_errno = errno;
            (void)close(descriptor);
            errno = saved_errno;
            return -1;
        }
        if (status.st_dev == output_status.st_dev && status.st_ino == output_status.st_ino) {
            (void)close(descriptor);
            errno = EINVAL;
            (void)fprintf(stderr, "%s: output and state files refer to the same file\n",
                PROGRAM_NAME);
            return -1;
        }
    }
    stream = fdopen(descriptor, "r");
    if (stream == NULL) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    *state_exists = true;
    (void)snprintf(expected, sizeof(expected),
        "READMEM_STATE_V3\t%s\t%s\t%016" PRIx64,
        emit_name(options->emit_mode), dedupe_name(options->dedupe_mode),
        options_state_hash(options));
    bytes_read = getline(&line, &capacity, stream);
    if (bytes_read < 0 || (uint64_t)bytes_read > options->max_state_size) {
        errno = bytes_read < 0 ? EINVAL : EFBIG;
        goto cleanup;
    }
    total_read = (uint64_t)bytes_read;
    length = (size_t)bytes_read;
    trim_line_ending(line, &length);
    if (strcmp(line, expected) != 0) {
        (void)fprintf(stderr, "%s: incompatible state-file header\n", PROGRAM_NAME);
        errno = EINVAL;
        goto cleanup;
    }
    while ((bytes_read = getline(&line, &capacity, stream)) >= 0) {
        char *first_tab, *second_tab, *end = NULL;
        uintmax_t address;
        char *mapping, *value;
        match_t *match;
        bool inserted;
        if ((uint64_t)bytes_read > options->max_state_size - total_read) {
            errno = EFBIG;
            goto cleanup;
        }
        total_read += (uint64_t)bytes_read;
        length = (size_t)bytes_read;
        trim_line_ending(line, &length);
        first_tab = strchr(line, '\t');
        second_tab = first_tab == NULL ? NULL : strchr(first_tab + 1, '\t');
        if (first_tab == NULL || second_tab == NULL) { errno = EINVAL; goto cleanup; }
        *first_tab = '\0';
        *second_tab = '\0';
        errno = 0;
        address = strtoumax(line, &end, 16);
        if (errno != 0 || end == line || *end != '\0' || address > UINTPTR_MAX) {
            errno = EINVAL;
            goto cleanup;
        }
        mapping = state_decode_hex(first_tab + 1);
        value = state_decode_hex(second_tab + 1);
        if (mapping == NULL || value == NULL) {
            free(mapping);
            free(value);
            goto cleanup;
        }
        match = calloc(1, sizeof(*match));
        if (match == NULL) { free(mapping); free(value); goto cleanup; }
        match->address = (uintptr_t)address;
        match->mapping = mapping;
        match->value = value;
        if (state->count >= options->max_results ||
            match_set_insert(state, match, &inserted) != 0) {
            match_destroy(match);
            if (state->count >= options->max_results) errno = EOVERFLOW;
            goto cleanup;
        }
        if (!inserted) match_destroy(match);
    }
    if (ferror(stream)) goto cleanup;
    result = 0;
cleanup:
    free(line);
    (void)fclose(stream);
    return result;
}

static int state_record_size(const match_t *match, uint64_t *size)
{
    size_t mapping_length = strlen(match->mapping);
    size_t value_length = strlen(match->value);
    uint64_t mapping_length_u64 = (uint64_t)mapping_length;
    uint64_t value_length_u64 = (uint64_t)value_length;
    uint64_t result = (uint64_t)(sizeof(uintptr_t) * 2U + 3U);
    if (mapping_length_u64 > (UINT64_MAX - result) / 2U) {
        errno = EOVERFLOW;
        return -1;
    }
    result += mapping_length_u64 * 2U;
    if (value_length_u64 > (UINT64_MAX - result) / 2U) {
        errno = EOVERFLOW;
        return -1;
    }
    *size = result + value_length_u64 * 2U;
    return 0;
}

static int state_save(const options_t *options, const match_set_t *state)
{
    char *temporary_path = NULL;
    int descriptor = -1;
    FILE *stream = NULL;
    size_t i;
    uint64_t bytes_written;
    char header[128];
    int header_length;
    int result = -1;
    if (options->state_path == NULL) return 0;
    if (asprintf(&temporary_path, "%s.tmp.XXXXXX", options->state_path) < 0) return -1;
    descriptor = mkstemp(temporary_path);
    if (descriptor < 0) goto cleanup;
    if (fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) goto cleanup;
    stream = fdopen(descriptor, "w");
    if (stream == NULL) goto cleanup;
    descriptor = -1;
    header_length = snprintf(header, sizeof(header),
        "READMEM_STATE_V3\t%s\t%s\t%016" PRIx64 "\n",
        emit_name(options->emit_mode), dedupe_name(options->dedupe_mode),
        options_state_hash(options));
    if (header_length < 0 || (size_t)header_length >= sizeof(header)) {
        errno = EOVERFLOW;
        goto cleanup;
    }
    bytes_written = (uint64_t)header_length;
    if (bytes_written > options->max_state_size ||
        !filesystem_has_room(fileno(stream), bytes_written, options->min_free_space) ||
        fwrite(header, 1U, (size_t)header_length, stream) != (size_t)header_length) goto cleanup;
    for (i = 0; i < state->capacity; ++i) {
        const match_t *match = state->slots[i];
        uint64_t record_size;
        if (match == NULL) continue;
        if (state_record_size(match, &record_size) != 0 ||
            record_size > options->max_state_size - bytes_written) {
            errno = EFBIG;
            goto cleanup;
        }
        if (!filesystem_has_room(fileno(stream), record_size, options->min_free_space))
            goto cleanup;
        if (fprintf(stream, "%" PRIxPTR "\t", match->address) < 0 ||
            state_write_hex(stream, match->mapping) != 0 || fputc('\t', stream) == EOF ||
            state_write_hex(stream, match->value) != 0 || fputc('\n', stream) == EOF) goto cleanup;
        bytes_written += record_size;
    }
    if (fflush(stream) != 0 || fsync(fileno(stream)) != 0) goto cleanup;
    if (fclose(stream) != 0) { stream = NULL; goto cleanup; }
    stream = NULL;
    if (rename(temporary_path, options->state_path) != 0) goto cleanup;
    result = 0;
cleanup:
    if (stream != NULL) (void)fclose(stream);
    if (descriptor >= 0) (void)close(descriptor);
    if (result != 0 && temporary_path != NULL) (void)unlink(temporary_path);
    free(temporary_path);
    return result;
}

static int acquire_state_lock(const options_t *options, char **lock_path)
{
    int descriptor;
    struct stat status;
    *lock_path = NULL;
    if (asprintf(lock_path, "%s.lock", options->state_path) < 0) return -1;
    descriptor = open(*lock_path,
        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        S_IRUSR | S_IWUSR);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &status) != 0) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1 ||
        status.st_uid != geteuid() || (status.st_mode & 07777U) != 0600U) {
        (void)close(descriptor);
        errno = EACCES;
        return -1;
    }
    if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
        int saved_errno = errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    return descriptor;
}

static int history_add_clone(match_set_t *history, const match_t *source, size_t limit)
{
    match_t *copy;
    bool inserted;
    if (match_set_find(history, source) != NULL) return 0;
    if (history->count >= limit) { errno = EOVERFLOW; return -1; }
    copy = match_clone(source);
    if (copy == NULL) return -1;
    if (match_set_insert(history, copy, &inserted) != 0) {
        match_destroy(copy);
        return -1;
    }
    if (!inserted) match_destroy(copy);
    return 0;
}

static int replace_history(match_set_t *history, const match_collection_t *current, size_t limit)
{
    match_set_t replacement;
    size_t i;
    if (match_set_init(&replacement, history->mode) != 0) return -1;
    for (i = 0; i < current->count; ++i) {
        if (history_add_clone(&replacement, current->items[i], limit) != 0) {
            match_set_destroy(&replacement, true);
            return -1;
        }
    }
    match_set_destroy(history, true);
    *history = replacement;
    return 0;
}

static bool history_equals_collection(const match_set_t *history,
    const match_collection_t *current)
{
    size_t i;

    if (history->count != current->count) return false;
    for (i = 0; i < current->count; ++i) {
        if (match_set_find(history, current->items[i]) == NULL) return false;
    }
    return true;
}

static commit_result_t commit_scan(const options_t *options, output_t *output,
    match_set_t *history, const match_collection_t *current,
    const match_collection_t *cycle_current, bool cycle_finished,
    bool cycle_complete, uint64_t scan_number, uint64_t cycle_number,
    const scan_stats_t *stats, bool *state_exists)
{
    char timestamp[32];
    size_t i;
    bool state_changed = !*state_exists;
    bool output_changed = false;
    bool limit_reached = false;
    output_write_result_t write_result;
    if (format_timestamp(timestamp) != 0) return COMMIT_ERROR;
    if (options->emit_mode == EMIT_ALL) {
        for (i = 0; i < current->count; ++i) {
            write_result = output_match(output, options, current->items[i], "match",
                scan_number, cycle_number, cycle_complete, timestamp);
            if (write_result == OUTPUT_WRITE_ERROR) return COMMIT_ERROR;
            if (write_result == OUTPUT_WRITE_LIMIT) { limit_reached = true; break; }
            output_changed = true;
        }
    } else if (options->emit_mode == EMIT_NEW) {
        for (i = 0; i < current->count; ++i) {
            if (match_set_find(history, current->items[i]) == NULL) {
                write_result = output_match(output, options, current->items[i], "found",
                    scan_number, cycle_number, cycle_complete, timestamp);
                if (write_result == OUTPUT_WRITE_ERROR) return COMMIT_ERROR;
                if (write_result == OUTPUT_WRITE_LIMIT) { limit_reached = true; break; }
                output_changed = true;
                if (history_add_clone(history, current->items[i], options->max_results) != 0)
                    return COMMIT_ERROR;
                state_changed = true;
            }
        }
    } else {
        for (i = 0; i < current->count; ++i) {
            bool is_new = match_set_find(history, current->items[i]) == NULL;
            if (is_new) {
                write_result = output_match(output, options, current->items[i], "found",
                    scan_number, cycle_number, cycle_complete, timestamp);
                if (write_result == OUTPUT_WRITE_ERROR) return COMMIT_ERROR;
                if (write_result == OUTPUT_WRITE_LIMIT) { limit_reached = true; break; }
                output_changed = true;
            }
        }
        if (!limit_reached && cycle_complete) {
            for (i = 0; i < history->capacity; ++i) {
                match_t *previous = history->slots[i];
                bool is_lost = previous != NULL &&
                    match_set_find(&cycle_current->index, previous) == NULL;
                if (is_lost) {
                    write_result = output_match(output, options, previous, "lost",
                        scan_number, cycle_number, true, timestamp);
                    if (write_result == OUTPUT_WRITE_ERROR) return COMMIT_ERROR;
                    if (write_result == OUTPUT_WRITE_LIMIT) { limit_reached = true; break; }
                    output_changed = true;
                }
            }
            if (!limit_reached && !history_equals_collection(history, cycle_current)) {
                if (replace_history(history, cycle_current, options->max_results) != 0)
                    return COMMIT_ERROR;
                state_changed = true;
            }
        } else if (!limit_reached) {
            for (i = 0; i < current->count; ++i) {
                if (match_set_find(history, current->items[i]) == NULL) {
                    if (history_add_clone(history, current->items[i], options->max_results) != 0)
                        return COMMIT_ERROR;
                    state_changed = true;
                }
            }
        }
    }
    if (!limit_reached && options->debug_output) {
        write_result = output_scan_summary(output, options, scan_number, cycle_number,
            cycle_finished, cycle_complete, stats, timestamp);
        if (write_result == OUTPUT_WRITE_ERROR) return COMMIT_ERROR;
        if (write_result == OUTPUT_WRITE_LIMIT) limit_reached = true;
        else if (output->format == FORMAT_JSONL) output_changed = true;
    }
    if (output_changed && output_flush(output) != 0) return COMMIT_ERROR;
    if (options->emit_mode != EMIT_ALL && state_changed) {
        if (state_save(options, history) != 0) return COMMIT_ERROR;
        *state_exists = true;
    }
    return limit_reached ? COMMIT_OUTPUT_LIMIT : COMMIT_OK;
}

static int sleep_interval(uint64_t interval_ns, uint64_t deadline_ns)
{
    struct timespec now, target;
    uint64_t now_ns, target_ns;
    int result;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    now_ns = timespec_to_ns(&now);
    target_ns = UINT64_MAX - now_ns < interval_ns ? UINT64_MAX : now_ns + interval_ns;
    if (deadline_ns != 0 && target_ns > deadline_ns) target_ns = deadline_ns;
    if (now_ns >= target_ns) return 0;
    target.tv_sec = (time_t)(target_ns / UINT64_C(1000000000));
    target.tv_nsec = (long)(target_ns % UINT64_C(1000000000));
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &target, NULL);
    } while (result == EINTR && !stop_requested);
    if (result != 0 && result != EINTR) { errno = result; return -1; }
    return 0;
}

static int lower_soft_limit(int resource, uint64_t bytes)
{
    struct rlimit limit;
    rlim_t requested = (rlim_t)bytes;
    if ((uintmax_t)requested != (uintmax_t)bytes) {
        errno = EOVERFLOW;
        return -1;
    }
    if (getrlimit(resource, &limit) != 0) return -1;
    if (limit.rlim_max != RLIM_INFINITY && requested > limit.rlim_max)
        requested = limit.rlim_max;
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur <= requested) return 0;
    limit.rlim_cur = requested;
    return setrlimit(resource, &limit);
}

static int apply_resource_limits(const options_t *options)
{
    struct rlimit core_limit = { 0, 0 };
    uint64_t file_limit = options->max_output_size > options->max_state_size ?
        options->max_output_size : options->max_state_size;
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0 ||
        lower_soft_limit(RLIMIT_AS, options->max_memory) != 0 ||
        lower_soft_limit(RLIMIT_FSIZE, file_limit) != 0) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    options_t options;
    matcher_t matcher;
    regex_list_t includes, excludes;
    output_t output;
    match_set_t history;
    match_collection_t cycle_current;
    scan_cursor_t scan_cursor = { 0 };
    size_t page_size;
    long system_page_size, system_iov_max;
    uint64_t initial_starttime;
    uint64_t scan_number = 0;
    uint64_t cycle_number = 1;
    uint64_t run_deadline_ns = 0;
    int state_lock = -1;
    char *state_lock_path = NULL;
    bool state_exists = false;
    bool cycle_current_initialized = false;
    bool cycle_clean = true;
    int result = EXIT_OK;
    struct sigaction action;

    (void)setlocale(LC_CTYPE, "");
    (void)umask(S_IRWXG | S_IRWXO);
    if (parse_options(argc, argv, &options) != 0) {
        print_usage(stderr);
        result = EXIT_USAGE_ERROR;
        goto free_option_lists;
    }
    if (apply_resource_limits(&options) != 0) {
        perror("set resource limits");
        result = EXIT_RUNTIME;
        goto free_option_lists;
    }
    if (matcher_init(&matcher, &options) != 0) {
        result = EXIT_USAGE_ERROR;
        goto free_option_lists;
    }
    if (regex_list_compile(&includes, &options.include_maps,
            "--include-map", REG_EXTENDED | REG_NOSUB) != 0) {
        result = EXIT_USAGE_ERROR;
        goto destroy_matcher;
    }
    if (regex_list_compile(&excludes, &options.exclude_maps,
            "--exclude-map", REG_EXTENDED | REG_NOSUB) != 0) {
        result = EXIT_USAGE_ERROR;
        goto destroy_includes;
    }
    system_page_size = sysconf(_SC_PAGESIZE);
    system_iov_max = sysconf(_SC_IOV_MAX);
    if (system_page_size <= 0 || system_iov_max <= 0 ||
        (uintmax_t)system_page_size > SIZE_MAX) {
        perror("sysconf");
        result = EXIT_RUNTIME;
        goto destroy_excludes;
    }
    page_size = (size_t)system_page_size;
    if (READ_CHUNK_SIZE / page_size + 2U > (size_t)system_iov_max) {
        (void)fprintf(stderr, "%s: system page size produces too many iovec entries\n",
            PROGRAM_NAME);
        result = EXIT_RUNTIME;
        goto destroy_excludes;
    }
    if (read_process_starttime(options.pid, &initial_starttime) != 0) {
        if (errno == EACCES || errno == EPERM) result = EXIT_PERMISSION_ERROR;
        else if (errno == ENOENT || errno == ESRCH) result = EXIT_TARGET_GONE;
        else result = EXIT_RUNTIME;
        perror("read target process identity");
        goto destroy_excludes;
    }
    options.target_starttime = initial_starttime;
    if (output_open(&output, &options) != 0) {
        perror("open output");
        result = EXIT_OUTPUT_ERROR;
        goto destroy_excludes;
    }
    if (options.emit_mode != EMIT_ALL) {
        if (match_set_init(&history, options.dedupe_mode) != 0) {
            perror("initialize state");
            result = EXIT_RUNTIME;
            goto close_output;
        }
        if (options.state_path != NULL) {
            state_lock = acquire_state_lock(&options, &state_lock_path);
            if (state_lock < 0) {
                perror("lock state file");
                result = EXIT_RUNTIME;
                goto destroy_history;
            }
            if (output.sync_file) {
                struct stat lock_status;
                struct stat output_status;
                if (fstat(state_lock, &lock_status) != 0 ||
                    fstat(fileno(output.stream), &output_status) != 0) {
                    perror("compare output and state lock files");
                    result = EXIT_RUNTIME;
                    goto destroy_history;
                }
                if (lock_status.st_dev == output_status.st_dev &&
                    lock_status.st_ino == output_status.st_ino) {
                    (void)fprintf(stderr,
                        "%s: output file cannot be the state lock file\n", PROGRAM_NAME);
                    result = EXIT_USAGE_ERROR;
                    goto destroy_history;
                }
            }
        }
        if (state_load(&options, &output, state_lock, &history, &state_exists) != 0) {
            perror("load state file");
            result = EXIT_RUNTIME;
            goto destroy_history;
        }
    } else memset(&history, 0, sizeof(history));
    memset(&cycle_current, 0, sizeof(cycle_current));
    if (options.emit_mode == EMIT_CHANGES) {
        if (collection_init(&cycle_current, options.dedupe_mode,
                options.max_results) != 0) {
            perror("initialize cycle result collection");
            result = EXIT_RUNTIME;
            goto destroy_history;
        }
        cycle_current_initialized = true;
    }
    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction");
        result = EXIT_RUNTIME;
        goto destroy_cycle;
    }
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGXFSZ, &action, NULL) != 0 ||
        sigaction(SIGPIPE, &action, NULL) != 0) {
        perror("sigaction ignored signals");
        result = EXIT_RUNTIME;
        goto destroy_cycle;
    }
    if (options.duration_set) {
        struct timespec run_started;
        uint64_t run_started_ns;
        if (clock_gettime(CLOCK_MONOTONIC, &run_started) != 0) {
            perror("clock_gettime");
            result = EXIT_RUNTIME;
            goto destroy_cycle;
        }
        run_started_ns = timespec_to_ns(&run_started);
        run_deadline_ns = UINT64_MAX - run_started_ns < options.duration_ns ?
            UINT64_MAX : run_started_ns + options.duration_ns;
    }
    log_message(&options, 1,
        "%s: scanning PID %d; format=%s emit=%s dedupe=%s match=%s strategy=%s debug=%s%s",
        PROGRAM_NAME, options.pid, format_name(options.output_format),
        emit_name(options.emit_mode), dedupe_name(options.dedupe_mode),
        options.discover ? "discover" : match_mode_name(options.match_mode),
        scan_strategy_name(options.scan_strategy),
        options.debug_output ? "on" : "off",
        options.interval_set ? " periodic" : " once");
    log_message(&options, 2,
        "%s: limits memory=%" PRIu64 " scan=%" PRIu64 " output=%" PRIu64
        " state=%" PRIu64 " free-space=%" PRIu64,
        PROGRAM_NAME, options.max_memory, options.max_scan_size,
        options.max_output_size, options.max_state_size, options.min_free_space);
    if (output_limit_reached(&output)) {
        log_message(&options, 1,
            "%s: output size limit already reached (%" PRIu64 " bytes)",
            PROGRAM_NAME, output.max_bytes);
    }

    while (!stop_requested && !output_limit_reached(&output) &&
        (options.iterations == 0 || scan_number < options.iterations)) {
        match_collection_t current;
        scan_stats_t stats = { 0 };
        scan_result_t scan_result;
        commit_result_t commit_result;
        struct timespec scan_started;
        uint64_t scan_started_ns, current_starttime;
        bool resumable;
        bool cycle_finished;
        bool cycle_complete;
        bool cycle_aborted;
        if (clock_gettime(CLOCK_MONOTONIC, &scan_started) != 0) {
            perror("clock_gettime");
            result = EXIT_RUNTIME;
            break;
        }
        scan_started_ns = timespec_to_ns(&scan_started);
        if (options.duration_set && scan_started_ns >= run_deadline_ns) break;
        scan_number++;
        if (read_process_starttime(options.pid, &current_starttime) != 0 ||
            current_starttime != initial_starttime) {
            (void)fprintf(stderr, "%s: target process exited or PID was reused\n", PROGRAM_NAME);
            result = EXIT_TARGET_GONE;
            break;
        }
        if (collection_init(&current, options.dedupe_mode, options.max_results) != 0) {
            perror("initialize result collection");
            result = EXIT_RUNTIME;
            break;
        }
        scan_result = scan_process(&options, &matcher, &includes, &excludes,
            &current, page_size, &stats, &scan_cursor);
        if (scan_result == SCAN_STOPPED) {
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            break;
        }
        if (scan_result == SCAN_TARGET_EXITED) {
            (void)fprintf(stderr, "%s: target process exited\n", PROGRAM_NAME);
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_TARGET_GONE;
            break;
        }
        if (scan_result == SCAN_PERMISSION_DENIED) {
            (void)fprintf(stderr, "%s: permission denied while reading target memory\n", PROGRAM_NAME);
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_PERMISSION_ERROR;
            break;
        }
        if (scan_result == SCAN_FATAL) {
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_RUNTIME;
            break;
        }
        if (read_process_starttime(options.pid, &current_starttime) != 0 ||
            current_starttime != initial_starttime) {
            (void)fprintf(stderr, "%s: target process changed during scan; results discarded\n",
                PROGRAM_NAME);
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_TARGET_GONE;
            break;
        }
        resumable = scan_result == SCAN_MORE;
        cycle_finished = stats.reached_end;
        cycle_clean = cycle_clean && !stats.incomplete;
        cycle_complete = cycle_finished && cycle_clean && scan_result == SCAN_COMPLETE;
        cycle_aborted = !resumable && !cycle_finished;
        if (scan_result == SCAN_PARTIAL && !options.best_effort) {
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_INCOMPLETE_SCAN;
            break;
        }
        if (options.emit_mode == EMIT_CHANGES &&
            collection_merge(&cycle_current, &current) != 0) {
            if (errno != EOVERFLOW) {
                perror("accumulate cycle results");
                collection_destroy(&current);
                scan_stats_destroy(&stats);
                result = EXIT_RUNTIME;
                break;
            }
            log_message(&options, 1,
                "%s: cycle result limit reached (%zu)",
                PROGRAM_NAME, options.max_results);
            if (!options.best_effort) {
                collection_destroy(&current);
                scan_stats_destroy(&stats);
                result = EXIT_INCOMPLETE_SCAN;
                break;
            }
            stats.incomplete = true;
            cycle_clean = false;
            cycle_finished = false;
            cycle_complete = false;
            cycle_aborted = true;
            scan_cursor_clear(&scan_cursor);
        }
        commit_result = commit_scan(&options, &output, &history, &current,
            &cycle_current, cycle_finished, cycle_complete, scan_number,
            cycle_number, &stats, &state_exists);
        if (commit_result == COMMIT_ERROR) {
            perror("commit scan results");
            collection_destroy(&current);
            scan_stats_destroy(&stats);
            result = EXIT_OUTPUT_ERROR;
            break;
        }
        log_message(&options, 2,
            "%s: scan=%" PRIu64 " cycle=%" PRIu64
            " cycle_finished=%s cycle_complete=%s mappings=%" PRIu64
            " bytes=%" PRIu64 " skipped_pages=%" PRIu64
            " unbacked_file_bytes=%" PRIu64 " limited_file_mappings=%" PRIu64
            " matches=%zu",
            PROGRAM_NAME, scan_number, cycle_number,
            cycle_finished ? "yes" : "no", cycle_complete ? "yes" : "no",
            stats.mappings_read,
            stats.bytes_read, stats.skipped_pages, stats.unbacked_file_bytes,
            stats.limited_file_mappings, current.count);
        collection_destroy(&current);
        scan_stats_destroy(&stats);
        if (commit_result == COMMIT_OUTPUT_LIMIT) {
            log_message(&options, 1,
                "%s: output size limit reached (%" PRIu64
                " bytes); no partial record was written",
                PROGRAM_NAME, output.max_bytes);
            break;
        }
        if (cycle_finished || cycle_aborted) {
            scan_cursor_clear(&scan_cursor);
            if (cycle_current_initialized) {
                collection_destroy(&cycle_current);
                if (collection_init(&cycle_current, options.dedupe_mode,
                        options.max_results) != 0) {
                    perror("reset cycle result collection");
                    cycle_current_initialized = false;
                    result = EXIT_RUNTIME;
                    break;
                }
            }
            cycle_number++;
            cycle_clean = true;
        }
        if (!options.interval_set ||
            (options.iterations != 0 && scan_number >= options.iterations)) break;
        if (options.duration_set) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
                perror("clock_gettime");
                result = EXIT_RUNTIME;
                break;
            }
            if (timespec_to_ns(&now) >= run_deadline_ns) break;
        }
        if (sleep_interval(options.interval_ns, run_deadline_ns) != 0) {
            perror("sleep");
            result = EXIT_RUNTIME;
            break;
        }
    }

    if (result == EXIT_OK && scan_cursor.active && !stop_requested &&
        !output_limit_reached(&output) && !options.best_effort) {
        log_message(&options, 1,
            "%s: scheduling ended before cycle %" PRIu64 " was complete; "
            "next address would be 0x%" PRIxPTR " in mapping '%s'",
            PROGRAM_NAME, cycle_number, scan_cursor.next_address,
            scan_cursor.mapping_name);
        result = EXIT_INCOMPLETE_SCAN;
    }

destroy_cycle:
    scan_cursor_clear(&scan_cursor);
    if (cycle_current_initialized) collection_destroy(&cycle_current);
destroy_history:
    if (options.emit_mode != EMIT_ALL) match_set_destroy(&history, true);
    if (state_lock >= 0) (void)close(state_lock);
    free(state_lock_path);
close_output:
    output_close(&output);
destroy_excludes:
    regex_list_destroy(&excludes);
destroy_includes:
    regex_list_destroy(&includes);
destroy_matcher:
    matcher_destroy(&matcher);
free_option_lists:
    free(options.regex_patterns.items);
    free(options.contains_patterns.items);
    free(options.exclude_regex_patterns.items);
    free(options.exclude_contains_patterns.items);
    free(options.include_maps.items);
    free(options.exclude_maps.items);
    return result;
}
