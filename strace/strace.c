#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <syscall.h>
#include <sys/ptrace.h>   

#define FATAL(ERR_MSG) error(1, 0, ERR_MSG)

// syscall table
const char *sysent[] = {
    #include "syscallent.h"
};

int main(int argc, char **argv) {
    
    if (argc != 2) {
        FATAL("Usage: ./strace <BINARY_PATH>\n");
    }

    pid_t child_pid = fork();

    switch (child_pid)
    {
    case -1:
        FATAL("fork faild");

    case 0:
        ptrace(PTRACE_TRACEME, NULL, NULL, NULL);

        /* Because we're now a tracee, execvp will block until the parent
        * attaches and allows us to continue. */
       execvp(argv[1], argv + 1);
       FATAL("execve() failed");
    }

    waitpid(child_pid, 0, 0); // sync with execvp

    // the tracee should be terminated along with its parent.
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);

    for (;;) {
        // enter the next syscall
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) == -1) {
            FATAL("ptrace(PTRACE_SYSCALL) failed");
        }

        // wait for the tracee to enter the desired state
        if (waitpid(child_pid, 0, 0) == -1) {
            FATAL("waitpid() failed");
        }

        // gather system call arguments
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
            FATAL("ptrace(PTRACE_GETREGS) failed");
        }

        long syscall_number = regs.orig_rax;

        printf("%s(%ld, %ld, %ld, %ld, %ld, %ld)",
               sysent[syscall_number],
               (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
               (long)regs.r10, (long)regs.r8,  (long)regs.r9);

        // Run syscall and stop on exit
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            FATAL("ptrace(PTRACE_SYSCALL) failed");
        }
        
        if (waitpid(child_pid, 0, 0) == -1) {
            FATAL("waitpid() failed");
        }

        // Get system call result 
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
            printf(" = ?\n");
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
        }

        // Print system call result */
        printf(" = %ld\n", (long)regs.rax);
    }












}