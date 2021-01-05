#include <sys/stat.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include "test_fs.h"

// ============================================================================
// Helper function
// ============================================================================

static int create_file(const char *file_path) {
    int fd;
    int flags = O_RDONLY | O_CREAT | O_TRUNC;
    int mode = 00666;
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
// Test cases for file
// ============================================================================

static int __test_write_read(const char *file_path) {
    char *write_str = "Hello World\n";
    int fd;

    fd = open(file_path, O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    close(fd);

    if (fs_check_file_content(file_path, write_str) < 0) {
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

static int __test_pwrite_pread(const char *file_path) {
    char *write_str = "Hello World\n";
    char read_buf[128] = { 0 };
    int ret, fd;

    fd = open(file_path, O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to pwrite");
    }
    if (pwrite(fd, write_str, strlen(write_str), 1) <= 0) {
        THROW_ERROR("failed to pwrite");
    }
    ret = pwrite(fd, write_str, strlen(write_str), -1);
    if (ret >= 0 || errno != EINVAL) {
        THROW_ERROR("check pwrite with negative offset fail");
    }
    close(fd);
    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to pread");
    }
    if (pread(fd, read_buf, sizeof(read_buf), 1) != strlen(write_str)) {
        THROW_ERROR("failed to pread");
    }
    if (strcmp(write_str, read_buf) != 0) {
        THROW_ERROR("the message read from the file is not as it was written");
    }
    ret = pread(fd, write_str, strlen(write_str), -1);
    if (ret >= 0 || errno != EINVAL) {
        THROW_ERROR("check pread with negative offset fail");
    }
    close(fd);
    return 0;
}

static int __test_writev_readv(const char *file_path) {
    const char *iov_msg[2] = {"hello_", "world!"};
    char read_buf[128] = { 0 };
    struct iovec iov[2];
    int fd, len = 0;

    fd = open(file_path, O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to writev");
    }
    for (int i = 0; i < 2; ++i) {
        iov[i].iov_base = (void *)iov_msg[i];
        iov[i].iov_len = strlen(iov_msg[i]);
        len += iov[i].iov_len;
    }
    if (writev(fd, iov, 2) != len) {
        THROW_ERROR("failed to write vectors to the file");
        return -1;
    }
    close(fd);
    fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to readv");
    }
    iov[0].iov_base = read_buf;
    iov[0].iov_len = strlen(iov_msg[0]);
    iov[1].iov_base = read_buf + strlen(iov_msg[0]);
    iov[1].iov_len = strlen(iov_msg[1]);
    if (readv(fd, iov, 2) != len) {
        THROW_ERROR("failed to read vectors from the file");
    }
    if (memcmp(read_buf, iov_msg[0], strlen(iov_msg[0])) != 0 ||
            memcmp(read_buf + strlen(iov_msg[0]), iov_msg[1], strlen(iov_msg[1])) != 0) {
        THROW_ERROR("the message read from the file is not as it was written");
    }
    close(fd);
    return 0;
}

static int __test_lseek(const char *file_path) {
    char *write_str = "Hello World\n";
    char read_buf[128] = { 0 };
    int fd, offset, ret;

    fd = open(file_path, O_RDWR);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to read/write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    /* make sure offset is in range (0, strlen(write_str)) */
    offset = 2;
    if (lseek(fd, offset, SEEK_SET) != offset) {
        THROW_ERROR("failed to lseek the file");
    }
    if (read(fd, read_buf, sizeof(read_buf)) >= strlen(write_str)) {
        THROW_ERROR("failed to read from offset");
    }
    if (strcmp(write_str + offset, read_buf) != 0) {
        THROW_ERROR("the message read from the offset is wrong");
    }
    offset = -1;
    ret = lseek(fd, offset, SEEK_SET);
    if (ret >= 0 || errno != EINVAL) {
        THROW_ERROR("check lseek with negative offset fail");
    }
    if (lseek(fd, 0, SEEK_END) != strlen(write_str)) {
        THROW_ERROR("faild to lseek to the end of the file");
    }
    close(fd);
    return 0;
}

typedef int(*test_file_func_t)(const char *);

static int test_file_framework(test_file_func_t fn) {
    const char *file_path = "/root/test_filesystem_file_read_write.txt";

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

static int test_write_read() {
    return test_file_framework(__test_write_read);
}

static int test_pwrite_pread() {
    return test_file_framework(__test_pwrite_pread);
}

static int test_writev_readv() {
    return test_file_framework(__test_writev_readv);
}

static int test_lseek() {
    return test_file_framework(__test_lseek);
}

static int test_write_read_hostfs () {
    printf("Test hostfs:");
    char *write_str = "Hello World\n";
    int fd;
    char *file_path = "/host/test_file.txt";

    fd = open(file_path, O_CREAT | O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    close(fd);

    if (fs_check_file_content(file_path, write_str) < 0) {
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

static int test_write_read_sefs () {
    printf("Test sefs:");
    char *write_str = "Hello World\n";
    int fd;
    char *file_path = "/tmp/test_file.txt";

    fd = open(file_path, O_CREAT | O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    close(fd);

    if (fs_check_file_content(file_path, write_str) < 0) {
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

static int test_write_read_ramfs () {
    printf("Test ramfs:");
    char *write_str = "Hello World\n";
    int fd;
    char *file_path = "/tmpfs/test_file.txt";

    fd = open(file_path, O_CREAT | O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    close(fd);

    if (fs_check_file_content(file_path, write_str) < 0) {
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

static int test_write_read_unionfs () {
    printf("Test unionfs:");
    char *write_str = "Hello World\n";
    int fd;
    char *file_path = "/root/test_file.txt";

    fd = open(file_path, O_CREAT | O_WRONLY);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }
    if (write(fd, write_str, strlen(write_str)) <= 0) {
        THROW_ERROR("failed to write");
    }
    close(fd);

    if (fs_check_file_content(file_path, write_str) < 0) {
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

struct thread_arg {
    char *user_buf;
    int fd;
};

void *thread_read_miss (void *arg) {
    struct thread_arg *get_arg = (struct thread_arg *) arg;
    char *file_str_base = "abcdefghijklmn";

    int offset = 0;
    // if (lseek(get_arg->fd, offset, SEEK_SET) != offset) {
    //     printf("failed to lseek the file\n");
    //     return NULL;
    // }

    // cache miss
    // this will take longer as a test
    size_t len = pread(get_arg->fd, get_arg->user_buf, 4096, 0);
    printf("read things: %s, read len = %d, str_len = %d\n", get_arg->user_buf, len,
           strlen(file_str_base));
    if (len != strlen(file_str_base)) {
        printf("failed to read the msg from file\n");
        return NULL;
    }

    // it will get what the file is (write should be invalid)
    if (strcmp(file_str_base, get_arg->user_buf) != 0) {
        printf("the message read from the file is not expected\n");
        return NULL;
    }

    printf("read original success\n");

    return NULL;
}

static int test_write_read_same_page_simutaniously () {
    printf("Test write read same page simutaniously:\n");

    char *write_str_new = "ABCDEFGHIJKLMN";
    int fd;
    char *file_path = "/root/test_same_page.txt";
    char *user_buf = malloc(4096);

    struct thread_arg *arg = (struct thread_arg *)malloc(sizeof(struct thread_arg));
    arg->user_buf = user_buf;
    fd = open(file_path, O_RDWR);
    if (fd < 0) {
        THROW_ERROR("failed to open a file to write");
    }

    arg->fd = fd;

    pthread_t child = 0;
    if (pthread_create(&child, NULL, &thread_read_miss, arg) != 0) {
        THROW_ERROR("create child thread failed");
    }

    int offset = 0;
    // if (lseek(fd, offset, SEEK_SET) != offset) {
    //     THROW_ERROR("failed to lseek the file");
    // }
    // this should cache miss and in the test read will wait for write to finish
    if (pwrite(fd, write_str_new, strlen(write_str_new), 0) <= 0) {
        THROW_ERROR("failed to write");
    }

    // wait for read to complete
    // sleep(1);

    // flush file cache
    fsync(fd);

    if (fs_check_file_content(file_path, write_str_new) < 0) {
        printf("This should fail\n");
        THROW_ERROR("failed to check file content");
    }

    return 0;
}

// ============================================================================
// Test suite main
// ============================================================================

static test_case_t test_cases[] = {
    // TEST_CASE(test_write_read_hostfs),
    // TEST_CASE(test_write_read_ramfs),
    // TEST_CASE(test_write_read_sefs),
    // TEST_CASE(test_write_read_unionfs),
    TEST_CASE(test_write_read_same_page_simutaniously),
    // TEST_CASE(test_writev_readv),
    // TEST_CASE(test_lseek),
};

int main(int argc, const char *argv[]) {
    return test_suite_run(test_cases, ARRAY_SIZE(test_cases));
}
