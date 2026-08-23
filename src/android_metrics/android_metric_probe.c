#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int open_counter(uint32_t type, uint64_t config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
}

static void print_counter(const char *name, uint32_t type, uint64_t config) {
    errno = 0;
    int fd = open_counter(type, config);
    int saved_errno = errno;
    printf(
        "\"%s\":{\"available\":%s,\"errno\":%d,\"error\":\"%s\"}",
        name,
        fd >= 0 ? "true" : "false",
        fd >= 0 ? 0 : saved_errno,
        fd >= 0 ? "" : strerror(saved_errno));
    if (fd >= 0) {
        close(fd);
    }
}

int main(void) {
    struct timespec process_time;
    struct timespec thread_time;
    struct rusage self_usage;
    struct rusage thread_usage;
    int process_clock = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &process_time);
    int thread_clock = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &thread_time);
    int self_rusage = getrusage(RUSAGE_SELF, &self_usage);
    int thread_rusage = getrusage(RUSAGE_THREAD, &thread_usage);

    printf("{");
    printf("\"clock_process_cputime_id\":%s,", process_clock == 0 ? "true" : "false");
    printf("\"clock_thread_cputime_id\":%s,", thread_clock == 0 ? "true" : "false");
    printf("\"getrusage_self\":%s,", self_rusage == 0 ? "true" : "false");
    printf("\"getrusage_thread\":%s,", thread_rusage == 0 ? "true" : "false");
    printf("\"proc_self_stat_readable\":%s,", access("/proc/self/stat", R_OK) == 0 ? "true" : "false");
    printf("\"proc_self_sched_readable\":%s,", access("/proc/self/sched", R_OK) == 0 ? "true" : "false");
    printf("\"proc_self_schedstat_readable\":%s,", access("/proc/self/schedstat", R_OK) == 0 ? "true" : "false");
    printf("\"proc_self_io_readable\":%s,", access("/proc/self/io", R_OK) == 0 ? "true" : "false");
    printf("\"perf_event_open\":{");
    print_counter("cpu_cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    printf(",");
    print_counter("instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS);
    printf(",");
    print_counter("cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES);
    printf(",");
    print_counter("cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
    printf(",");
    print_counter("branch_instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
    printf(",");
    print_counter("branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES);
    printf(",");
    print_counter("context_switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES);
    printf(",");
    print_counter("page_faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS);
    printf("}}");
    return 0;
}
