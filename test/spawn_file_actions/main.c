#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <spawn.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>

#define mesg "hello world"
#define buf_len 12

// int main(int argc, const char *argv[]) {
//     int ret, child_pid, status;
//     printf("Run a parent process has pid = %d and ppid = %d\n", getpid(), getppid());

//     posix_spawn_file_actions_t actions;
//     posix_spawn_file_actions_init(&actions);

//     int new_fd = STDOUT_FILENO;
//     posix_spawn_file_actions_addopen(&actions, new_fd, "/tmp/test.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);

//     ret = posix_spawn(&child_pid, "/bin/cout", &actions, NULL, NULL, NULL);
//     if (ret < 0) {
//         printf("ERROR: failed to spawn a child process\n");
//         return -1;
//     }
//     printf("Spawn a new proces successfully (pid = %d)\n", child_pid);

//     ret = wait4(-1, &status, 0, NULL);
//     if (ret < 0) {
//         printf("ERROR: failed to wait4 the child process\n");
//         return -1;
//     }
//     printf("Child process exited with status = %d\n", status);

//     FILE *result = fopen("/tmp/test.txt", "r");
//     char buf[buf_len] = {0};
//     fread(buf, 1, buf_len, result);
//     if (strncmp(buf, mesg, buf_len - 1) != 0) {
//         printf("ERROR: the mesg is wrong\n");
//         return -1;
//     } else {
//         printf("mesg is correct\n");
//     }
//     fclose(result);

//     return 0;
// }

// void sigchld_handler(int sig)
// {
//   pid_t pid = getpid();
//   printf("In SIGCHLD signal handler of process %d\n", pid);

//   exit(-1);
// }

static void *thread_func(void *_arg) {
    struct __sigset_t current_block_sigmask;
    sigprocmask(0, NULL, &current_block_sigmask);
    struct __sigset_t test;
    sigemptyset(&test);
    sigaddset(&test, SIGALRM);
    sigprocmask(SIG_BLOCK, &test, NULL);
}


void sigchld_handler(int sig) {
    printf("SIGCHLD is caught in father process!\n");
    // exit(-1);
}

void sigio_handler(int sig) {
    printf("SIGIO is caught in father process!\n");
    // exit(-1);
}

// Block SIGIO and SIGABORT, ignore SIGIO in father process and unblock SIGIO, reset to default for SIGIO, block SIGABORT in child process.
int main(int argc, const char *argv[]) {
    int ret, child_pid, status;
    printf("Run a parent process has pid = %d and ppid = %d\n", getpid(), getppid());

    signal(SIGIO, sigio_handler);
    struct __sigset_t sig_set, sig_set2;
    sigemptyset (&sig_set);
    sigaddset(&sig_set, SIGIO);
    sigaddset(&sig_set, SIGABRT);
    sigprocmask(SIG_BLOCK, &sig_set, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, thread_func, NULL);

    pthread_join(tid, NULL);
    struct __sigset_t current_block_sigmask_master;
    sigprocmask(0, NULL, &current_block_sigmask_master);
    assert(current_block_sigmask_master.__bits[0] == sig_set.__bits[0]);

    raise(SIGIO);
    raise(SIGABRT);

    signal(SIGIO, SIG_IGN);
    signal(SIGCHLD, sigchld_handler);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
    // // posix_spawnattr_setsigdefault(&attr, &sig_set);
    sigdelset(&sig_set, SIGIO); // unblock SIGIO
    // sigprocmask(SIG_BLOCK, &sig_set, NULL);
    posix_spawnattr_setsigmask(&attr, &sig_set);
    sigaddset(&sig_set2, SIGIO);
    // posix_spawnattr_setsigdefault(&attr, &sig_set2);

    // new spawn process will inherit the SIGCHLD handler
    ret = posix_spawn(&child_pid, "/bin/naughty_child", NULL, &attr, NULL, NULL);
    if (ret < 0) {
        printf("ERROR: failed to spawn a child process\n");
        return -1;
    }
    printf("Spawn a new proces successfully (pid = %d)\n", child_pid);

    ret = waitpid(child_pid, &status, WNOHANG);
    if (ret < 0) {
        printf("ERROR: failed to wait4 the child process\n");
        return -1;
    }
    printf("wait no hang = %d\n", status);

    ret = waitpid(child_pid, &status, 0);
    if (ret < 0) {
        printf("ERROR: failed to wait4 the child process\n");
        return -1;
    }
    printf("child process %d exit status = %d\n", child_pid, status);
    return 0;
}
