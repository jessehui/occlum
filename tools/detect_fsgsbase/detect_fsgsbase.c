#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <ucontext.h>
#include <setjmp.h>
#include <stdlib.h>
#include <errno.h>

#define RC 0xffff
jmp_buf env_buf;

static void handle_sigill(int num) {
    printf("\tSIGILL Caught !\n");
    assert(num == SIGILL);
    printf("\tFSGSBASE instructions are not supported.\n");

    // since we don't know how far we should jump, just use longjmp to exit
    longjmp(env_buf, RC);
}

int main (void) {
    int gs_test_data = 0x0f;
    int __seg_gs *offset_ptr = 0;   // offset relative to GS. support since gcc-6

    signal(SIGILL, handle_sigill);
    if (errno != 0) {
        printf("registering signal handler failed");
        return errno;
    }

    int val = setjmp(env_buf);
    if (val == RC) {
        exit(1);
    }

    // Check if kernel supports FSGSBASE
    asm("wrgsbase %0" :: "r" (&gs_test_data));

    if (*offset_ptr != 0x0f) {
        printf("Uknown error\n");
        return -1;
    };

    printf("FSGSBASE instructions are supported.\n");
    return 0;
}
