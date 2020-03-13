#define _GNU_SOURCE
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <spawn.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "test.h"
#include <syslog.h>

// ============================================================================
// Test cases for sched_cpu_affinity
// ============================================================================

static int test_sched_getaffinity_with_self_pid() {
    cpu_set_t mask;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) < 0) {
        THROW_ERROR("failed to call sched_getaffinity");
    }
    if (CPU_COUNT(&mask) <= 0) {
        THROW_ERROR("failed to get cpuset mask");
    }
    if (sysconf(_SC_NPROCESSORS_ONLN) != CPU_COUNT(&mask)) {
        THROW_ERROR("cpuset num wrong");
    }
    return 0;
}

static unsigned long GetCpuMask(cpu_set_t* cpuSet)
{
    unsigned long mask = 0;
    const int maxCpus = CPU_SETSIZE < 64?CPU_SETSIZE:64;
    for (int cpu = 0; cpu < maxCpus; cpu++){
        mask |= CPU_ISSET(cpu, cpuSet)? 1ll<<cpu : 0;
    }
    return mask;
}

unsigned long GetThreadAffinityMask()
{
    cpu_set_t cpuSet;

    if (!sched_getaffinity(0, sizeof(cpu_set_t), &cpuSet)){
        return GetCpuMask(&cpuSet);
    }
    syslog (LOG_ERR, "sched_getaffinity fails, errno %d:%s", errno, strerror(errno));
    return 0;
}

static int test_sched_setaffinity_with_self_pid() {
    int nproc = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t mask_old;
    for (int i = 0; i < nproc; ++i) {
        CPU_SET(i, &mask_old);
    }

    cpu_set_t testCpuSet;
    for (int cpu = 0; cpu < 16; cpu++){
        CPU_ZERO(&testCpuSet);
        CPU_SET(cpu, &testCpuSet);
        unsigned long try_mask = GetCpuMask(&testCpuSet);
        if (!sched_setaffinity(0, sizeof(cpu_set_t), &testCpuSet)){
            syslog (LOG_INFO, "sched_setaffinity OK, cpu %d (mask 0x%x)",cpu, try_mask);
            unsigned long new_mask = GetThreadAffinityMask();
            syslog (LOG_INFO, "new_mask 0x%x", new_mask);
        } else {
            syslog (LOG_INFO, "sched_setaffinity, cpu %d errno %d:%s", cpu, errno, strerror(errno));
        }
    }

    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) < 0) {
        THROW_ERROR("failed to call sched_setaffinity \n");
    }
    cpu_set_t mask2;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask2) < 0) {
        THROW_ERROR("failed to call sched_getaffinity");
    }
    if (!CPU_EQUAL(&mask, &mask2)) {
        THROW_ERROR("cpuset is wrong after get");
    }
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask_old) < 0) {
        THROW_ERROR("recover cpuset error");
    }
    return 0;
}

static int test_sched_xetaffinity_with_child_pid() {
    int status, child_pid;
    int num = sysconf(_SC_NPROCESSORS_CONF);
    if (num <= 0) {
        THROW_ERROR("failed to get cpu number");
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(num - 1 , &mask);
    int ret = posix_spawn(&child_pid, "/bin/getpid", NULL, NULL, NULL, NULL);
    if (ret < 0 ) {
        THROW_ERROR("spawn process error");
    }
    printf("Spawn a child process with pid=%d\n", child_pid);
    if (sched_setaffinity(child_pid, sizeof(cpu_set_t), &mask) < 0) {
        THROW_ERROR("failed to set child affinity");
    }
    cpu_set_t mask2;
    if (sched_getaffinity(child_pid, sizeof(cpu_set_t), &mask2) < 0) {
        THROW_ERROR("failed to get child affinity");
    }
    if (!CPU_EQUAL(&mask, &mask2)) {
        THROW_ERROR("cpuset is wrong in child");
    }
    ret = wait4(-1, &status, 0, NULL);
    if (ret < 0) {
        THROW_ERROR("failed to wait4 the child proces");
    }
    return 0;
}

#define CPU_SET_SIZE_LIMIT (1024)

static int test_sched_getaffinity_via_explicit_syscall() {
    unsigned char buf[CPU_SET_SIZE_LIMIT] = { 0 };
    int ret = syscall(__NR_sched_getaffinity, 0, CPU_SET_SIZE_LIMIT, buf);
    if (ret <= 0) {
        THROW_ERROR("failed to call __NR_sched_getaffinity");
    }
    return 0;
}

static int test_sched_setaffinity_via_explicit_syscall() {
    int nproc = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t mask_old;
    for (int i = 0; i < nproc; ++i) {
        CPU_SET(i, &mask_old);
    }
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    if (syscall(__NR_sched_setaffinity, 0, sizeof(cpu_set_t), &mask) < 0) {
        THROW_ERROR("failed to call __NR_sched_setaffinity");
    }
    cpu_set_t mask2;
    int ret_nproc = syscall(__NR_sched_getaffinity, 0, sizeof(cpu_set_t), &mask2);
    if (ret_nproc <= 0) {
        THROW_ERROR("failed to call __NR_sched_getaffinity");
    }
    if (!CPU_EQUAL(&mask, &mask2)) {
        THROW_ERROR("explicit syscall cpuset is wrong");
    }
    if (syscall(__NR_sched_setaffinity, 0, sizeof(cpu_set_t), &mask_old) < 0) {
        THROW_ERROR("recover cpuset error");
    }
    return 0;
}

static int test_sched_getaffinity_with_zero_cpusetsize() {
    cpu_set_t mask;
    if (sched_getaffinity(0, 0, &mask) != -1) {
        THROW_ERROR("check invalid cpusetsize(0) fail");
    }
    return 0;
}

static int test_sched_setaffinity_with_zero_cpusetsize() {
    cpu_set_t mask;
    if (sched_setaffinity(0, 0, &mask) != -1) {
        THROW_ERROR("check invalid cpusetsize(0) fail");
    }
    return 0;
}

static int test_sched_getaffinity_with_null_buffer() {
    unsigned char *buf = NULL;
    if (sched_getaffinity(0, sizeof(cpu_set_t), (cpu_set_t*)buf) != -1) {
        THROW_ERROR("check invalid buffer pointer(NULL) fail");
    }
    return 0;
}

static int test_sched_setaffinity_with_null_buffer() {
    unsigned char *buf = NULL;
    if (sched_setaffinity(0, sizeof(cpu_set_t), (cpu_set_t*)buf) != -1) {
        THROW_ERROR("check invalid buffer pointer(NULL) fail");
    }
    return 0;
}

// ============================================================================
// Test cases for sched_yield
// ============================================================================

static int test_sched_yield() {
    // In the Linux implementation, sched_yield() always succeeds.
    if (sched_yield() < 0) {
        THROW_ERROR("check sched yield fail");
    }
    return 0;
}

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    TEST_CASE(test_sched_xetaffinity_with_child_pid),
    TEST_CASE(test_sched_getaffinity_with_self_pid),
    TEST_CASE(test_sched_setaffinity_with_self_pid),
    TEST_CASE(test_sched_getaffinity_via_explicit_syscall),
    TEST_CASE(test_sched_setaffinity_via_explicit_syscall),
    TEST_CASE(test_sched_getaffinity_with_zero_cpusetsize),
    TEST_CASE(test_sched_setaffinity_with_zero_cpusetsize),
    TEST_CASE(test_sched_getaffinity_with_null_buffer),
    TEST_CASE(test_sched_setaffinity_with_null_buffer),
    TEST_CASE(test_sched_yield),
};

int main() {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
