#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <assert.h>
// #include <sigset.h>

void sigio_handler(int sig) {
    printf("SIGIO is caught in child!\n");
    // exit(-1);
}

void sigabort_handler(int sig) {
    printf("sigabort is caught in child!\n");
}

int main(int argc, const char *argv[]) {
    printf("Run a new process with pid = %d and ppid = %d\n", getpid(), getppid());

    struct __sigset_t current_block_sigmask;
    sigprocmask(0, NULL, &current_block_sigmask);
    struct __sigset_t test;
    sigemptyset(&test);
    sigaddset(&test, SIGABRT);
    assert(current_block_sigmask.__bits[0] == test.__bits[0]);
    // signal(SIGIO, sigio_handler);
    struct sigaction act1, act2, act3;
    sigaction(SIGIO, NULL, &act1);
    sigaction(SIGABRT, NULL, &act2);
    sigaction(SIGCHLD, NULL, &act3);
    assert(act1.sa_handler = SIG_IGN);
    assert(act2.sa_handler == SIG_DFL);
    assert(act3.sa_handler == SIG_DFL);

    raise(SIGIO);

    signal(SIGABRT, sigabort_handler);
    raise(SIGABRT);

    sleep(3);
    return 0;
}
