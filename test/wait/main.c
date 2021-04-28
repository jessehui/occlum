#define _GNU_SOURCE
#include <sys/wait.h>
#include <errno.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include "test.h"

// ============================================================================
// Helper function
// ============================================================================
/*
static int create_file(const char *file_path) {
    int fd;
    int flags = O_RDONLY | O_CREAT | O_TRUNC;
    int mode = 00444;

    fd = open(file_path, flags, mode);
    if (fd < 0) {
        THROW_ERROR("failed to create a file");
    }
    close(fd);
    return 0;
}

static int remove_file(const char *file_path) {
    int ret;

    ret = unlink(file_path);
    if (ret < 0) {
        THROW_ERROR("failed to unlink the created file");
    }
    return 0;
}

// ============================================================================
// Test cases for chown
// ============================================================================

static int __test_chown(const char *file_path) {
    struct stat stat_buf;
    uid_t uid = 100;
    gid_t gid = 1000;
    int ret;

    ret = chown(file_path, uid, gid);
    if (ret < 0) {
        THROW_ERROR("failed to chown file");
    }
    ret = stat(file_path, &stat_buf);
    if (ret < 0) {
        THROW_ERROR("failed to stat file");
    }
    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        THROW_ERROR("check chown result failed");
    }
    return 0;
}

static int __test_lchown(const char *file_path) {
    struct stat stat_buf;
    uid_t uid = 100;
    gid_t gid = 1000;
    int ret;

    ret = lchown(file_path, uid, gid);
    if (ret < 0) {
        THROW_ERROR("failed to lchown file");
    }
    ret = stat(file_path, &stat_buf);
    if (ret < 0) {
        THROW_ERROR("failed to stat file");
    }
    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        THROW_ERROR("check lchown result failed");
    }
    return 0;
}

static int __test_fchown(const char *file_path) {
    struct stat stat_buf;
    uid_t uid = 100;
    gid_t gid = 1000;
    int fd, ret;

    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open file");
    }
    ret = fchown(fd, uid, gid);
    if (ret < 0) {
        THROW_ERROR("failed to fchown file");
    }
    close(fd);
    ret = stat(file_path, &stat_buf);
    if (ret < 0) {
        THROW_ERROR("failed to stat file");
    }
    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        THROW_ERROR("check fchown result failed");
    }
    return 0;
}

static int __test_fchownat(const char *file_path) {
    struct stat stat_buf;
    uid_t uid = 100;
    gid_t gid = 1000;
    char dir_buf[PATH_MAX] = { 0 };
    char base_buf[PATH_MAX] = { 0 };
    char *dir_name, *file_name;
    int dirfd, ret;

    if (fs_split_path(file_path, dir_buf, &dir_name, base_buf, &file_name) < 0) {
        THROW_ERROR("failed to split path");
    }
    dirfd = open(dir_name, O_RDONLY);
    if (dirfd < 0) {
        THROW_ERROR("failed to open dir");
    }
    ret = fchownat(dirfd, file_name, uid, gid, 0);
    if (ret < 0) {
        THROW_ERROR("failed to fchownat file with dirfd");
    }
    close(dirfd);
    ret = stat(file_path, &stat_buf);
    if (ret < 0) {
        THROW_ERROR("failed to stat file");
    }
    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        THROW_ERROR("check fchownat result failed");
    }
    return 0;
}

static int __test_fchownat_with_empty_path(const char *file_path) {
    struct stat stat_buf;
    uid_t uid = 100;
    gid_t gid = 1000;
    char dir_buf[128] = { 0 };
    char *dir_name;
    int dirfd, ret;

    if (fs_split_path(file_path, dir_buf, &dir_name, NULL, NULL) < 0) {
        THROW_ERROR("failed to split path");
    }
    dirfd = open(dir_name, O_RDONLY);
    if (dirfd < 0) {
        THROW_ERROR("failed to open dir");
    }

    ret = fchownat(dirfd, "", uid, gid, 0);
    if (!(ret < 0 && errno == ENOENT)) {
        THROW_ERROR("fchownat with empty path should return ENOENT");
    }

    ret = fchownat(dirfd, "", uid, gid, AT_EMPTY_PATH);
    if (ret < 0) {
        THROW_ERROR("failed to fchownat with empty path");
    }
    close(dirfd);
    ret = stat(dir_name, &stat_buf);
    if (ret < 0) {
        THROW_ERROR("failed to stat dir");
    }
    if (stat_buf.st_uid != uid || stat_buf.st_gid != gid) {
        THROW_ERROR("check fchownat result failed");
    }
    return 0;
}

typedef int(*test_chown_func_t)(const char *);

static int test_chown_framework(test_chown_func_t fn) {
    const char *file_path = "/root/test_filesystem_chown.txt";

    if (create_file(file_path) < 0) {
        return -1;
    }
    if (fn(file_path) < 0) {
        return -1;
    }
    if (remove_file(file_path) < 0) {
        return -1;
    }
    return 0;
}
*/

static int test_wait_no_children() {
    int status = 0;
    int ret = wait(&status);
    if (ret != -1 || errno != ECHILD) {
        THROW_ERROR("wait no children error");
    }
    return 0;
}

static int test_wait_nohang() {
    int status = 0;
    int ret = waitpid(-1, &status, WNOHANG);
    if (ret != -1 || errno != ECHILD) {
        THROW_ERROR("wait no children with NOHANG error");
    }

    int child_pid = 0;
    // /bin/sleep lasts more than 1 sec
    if (posix_spawn(&child_pid, "/bin/sleep", NULL, NULL, NULL, NULL) < 0) {
        THROW_ERROR("posix_spawn child error");
    }

    ret = waitpid(child_pid, &status, WNOHANG);
    if (ret != 0) {
        THROW_ERROR("wait child with NOHANG error");
    }

    sleep(2);
    ret = waitpid(child_pid, &status, WNOHANG);
    if (ret != child_pid) {
        THROW_ERROR("wait child with NOHANG error");
    }
    return 0;
}

// WUNTRACED is same as WSTOPPED
static int test_wait_untraced() {
    int status = 0;
    int ret = waitpid(-1, &status, WNOHANG);
    if (ret != -1 || errno != ECHILD) {
        THROW_ERROR("wait no children with NOHANG error");
    }

    int child_pid = 0;
    // char** argv_new = calloc(1, sizeof(char*)*1);
    // argv_new[0] = NULL;
    // /bin/sleep lasts more than 1 sec
    if (posix_spawn(&child_pid, "/bin/sleep", NULL, NULL, NULL, NULL) < 0) {
        THROW_ERROR("posix_spawn child error");
    }

    ret = waitpid(child_pid, &status, WNOHANG);
    if (ret != 0) {
        THROW_ERROR("wait child with NOHANG error");
    }

    kill(child_pid, SIGSTOP);
    // WUNTRACED will get child_pid status
    ret = waitpid(child_pid, &status, WUNTRACED);
    printf("ret = %d, status = %d\n", ret, status);
    if (ret != child_pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP ) {
        THROW_ERROR("wait child status error");
    }

    // Let child get back to running
    kill(child_pid, SIGCONT);

    sleep(2);
    ret = waitpid(child_pid, &status, WNOHANG | WUNTRACED);
    printf("ret = %d, status = %d\n", ret, status);
    if (ret != child_pid || !WIFEXITED(status) ) {
        THROW_ERROR("wait child with NOHANG error");
    }
    return 0;
}

// void sigalarm_handler(int sig) {
//     printf("handle sigalarm");
// }

// static int test_wait_multiple_children() {
//     int status = 0;
//     int ret = waitpid(-1, &status, WNOHANG);
//     if (ret != -1 || errno != ECHILD) {
//         THROW_ERROR("wait no children with NOHANG error");
//     }
//     signal(SIGALRM, sigalarm_handler);

//     int children_pids[3] = {0};
//     int child_num = 3;
//     // /bin/sleep lasts more than 1 sec
//     for (int i = 0; i< child_num; i++) {
//         if (posix_spawn(&children_pids[i], "/bin/sleep", NULL, NULL, NULL, NULL) < 0) {
//             THROW_ERROR("posix_spawn child error");
//         }
//     }

//     // SIGSTOP all children and SIGTERM child-0
//     kill(children_pids[1], SIGSTOP);
//     kill(children_pids[0], SIGTERM);
//     kill(children_pids[2], SIGSTOP);
//     // WUNTRACED will get child_pid status
//     waitpid(-1, &status, WUNTRACED);
//     bool tmp1 = WIFSTOPPED(status);
//     bool tmp2 = WIFSIGNALED(status);
//     int sig2 = WTERMSIG(status);
//     int signum = WSTOPSIG(status);
//     printf("status = %d, tmp1 = %d, tmp2 = %d, sig2 = %d, signum = %d\n",status, tmp1, tmp2, sig2, signum);
//     // if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP ) {
//     //     // kill(-1, SIGTERM);
//     //     // waitpid(-1, NULL, 0);
//     //     THROW_ERROR("wait child status error");
//     // }

//     // SIGCONT child-1, child-2 keep stopping
//     kill(children_pids[1], SIGCONT);
//     waitpid(-1, &status, WUNTRACED | WNOHANG | WCONTINUED);
//     tmp1 = WIFSTOPPED(status);
//     tmp2 = WIFSIGNALED(status);
//     bool tmp3 = WIFCONTINUED(status);
//     signum = WSTOPSIG(status);
//     printf("status = %d, tmp1 = %d, tmp2 = %d, tmp3 = %d, signum = %d\n", status, tmp1, tmp2, tmp3, signum);
//     // if(!WIFCONTINUED(status)) {
//     //     // kill(-1, SIGTERM);
//     //     // waitpid(-1, NULL, 0);
//     //     THROW_ERROR("wait child status error");
//     // }

//     // SIGTERM child-1 and child-2
//     kill(children_pids[1], SIGTERM);
//     kill(children_pids[2], SIGTERM);
//     ret = waitpid(-1, &status, WNOHANG | WUNTRACED);
//     sig2 = WSTOPSIG(status);
//     signum = WTERMSIG(status);
//     printf("status = %d, sig2 = %d, signum = %d\n", status, sig2, signum);
//     if (ret != children_pids[1] || !WIFEXITED(status) || !WIFSIGNALED(status)) {
//         // kill(-1, SIGKILL);
//         // waitpid(-1, NULL, 0);
//         THROW_ERROR("wait child with NOHANG error");
//     }
//     return 0;
// }

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    // TEST_CASE(test_wait_no_children),
    // TEST_CASE(test_wait_nohang),
    TEST_CASE(test_wait_untraced),
    // TEST_CASE(test_wait_multiple_children),
    // TEST_CASE(test_fchown),
    // TEST_CASE(test_fchownat),
    // TEST_CASE(test_fchownat_with_empty_path),
};

int main(int argc, const char *argv[]) {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
