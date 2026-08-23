#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct counter {
    const char *name;
    uint32_t type;
    uint64_t config;
    int fd;
    int open_errno;
    uint64_t value;
    int value_available;
};

static int perf_open(pid_t pid, uint32_t type, uint64_t config) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return (int)syscall(__NR_perf_event_open, &attr, pid, -1, -1, 0);
}

static uint64_t timeval_us(struct timeval value) {
    return (uint64_t)value.tv_sec * 1000000ULL + (uint64_t)value.tv_usec;
}

static void write_json(
    const char *path,
    struct counter *counters,
    size_t count,
    int child_status,
    const struct rusage *usage) {
    FILE *output = fopen(path, "w");
    if (output == NULL) {
        return;
    }
    fprintf(output, "{\n");
    fprintf(output, "  \"schema_version\": \"thinwallet-android-phase5-perf-v1\",\n");
    fprintf(output, "  \"child_wait_status\": %d,\n", child_status);
    fprintf(output, "  \"user_cpu_us\": %llu,\n", (unsigned long long)timeval_us(usage->ru_utime));
    fprintf(output, "  \"system_cpu_us\": %llu,\n", (unsigned long long)timeval_us(usage->ru_stime));
    fprintf(output, "  \"minor_page_faults\": %ld,\n", usage->ru_minflt);
    fprintf(output, "  \"major_page_faults\": %ld,\n", usage->ru_majflt);
    fprintf(output, "  \"voluntary_context_switches\": %ld,\n", usage->ru_nvcsw);
    fprintf(output, "  \"involuntary_context_switches\": %ld,\n", usage->ru_nivcsw);
    fprintf(output, "  \"counters\": {\n");
    for (size_t index = 0; index < count; index++) {
        struct counter *counter = &counters[index];
        fprintf(output, "    \"%s\": {\"value\": ", counter->name);
        if (counter->value_available) {
            fprintf(output, "%llu", (unsigned long long)counter->value);
        } else {
            fprintf(output, "null");
        }
        fprintf(
            output,
            ", \"open_errno\": %d, \"readable\": %s}%s\n",
            counter->open_errno,
            counter->value_available ? "true" : "false",
            index + 1 == count ? "" : ",");
    }
    fprintf(output, "  }\n}\n");
    fclose(output);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s OUTPUT_JSON COMMAND [ARGS...]\n", argv[0]);
        return 2;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child == 0) {
        raise(SIGSTOP);
        execvp(argv[2], &argv[2]);
        perror("execvp");
        _exit(127);
    }

    int stopped_status = 0;
    if (waitpid(child, &stopped_status, WUNTRACED) != child || !WIFSTOPPED(stopped_status)) {
        fprintf(stderr, "child did not stop before perf attachment\n");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 2;
    }

    const char *pid_path = getenv("THINWALLET_METRIC_CHILD_PID_PATH");
    if (pid_path != NULL) {
        FILE *pid_file = fopen(pid_path, "w");
        if (pid_file != NULL) {
            fprintf(pid_file, "%d\n", child);
            fclose(pid_file);
        }
    }

    struct counter counters[] = {
        {"task_clock_ns", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, -1, 0, 0, 0},
        {"cpu_cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, -1, 0, 0, 0},
        {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, -1, 0, 0, 0},
        {"cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, -1, 0, 0, 0},
        {"cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, -1, 0, 0, 0},
        {"branch_instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS, -1, 0, 0, 0},
        {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, -1, 0, 0, 0},
        {"context_switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, -1, 0, 0, 0},
        {"page_faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS, -1, 0, 0, 0},
    };
    size_t counter_count = sizeof(counters) / sizeof(counters[0]);
    for (size_t index = 0; index < counter_count; index++) {
        errno = 0;
        counters[index].fd = perf_open(child, counters[index].type, counters[index].config);
        counters[index].open_errno = counters[index].fd >= 0 ? 0 : errno;
        if (counters[index].fd >= 0) {
            ioctl(counters[index].fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(counters[index].fd, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    kill(child, SIGCONT);
    int child_status = 0;
    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    if (wait4(child, &child_status, 0, &usage) != child) {
        perror("wait4");
        child_status = 2 << 8;
    }

    for (size_t index = 0; index < counter_count; index++) {
        if (counters[index].fd < 0) {
            continue;
        }
        ioctl(counters[index].fd, PERF_EVENT_IOC_DISABLE, 0);
        uint64_t value = 0;
        ssize_t bytes = read(counters[index].fd, &value, sizeof(value));
        if (bytes == (ssize_t)sizeof(value)) {
            counters[index].value = value;
            counters[index].value_available = 1;
        }
        close(counters[index].fd);
    }
    write_json(argv[1], counters, counter_count, child_status, &usage);

    if (WIFEXITED(child_status)) {
        return WEXITSTATUS(child_status);
    }
    if (WIFSIGNALED(child_status)) {
        return 128 + WTERMSIG(child_status);
    }
    return 2;
}
