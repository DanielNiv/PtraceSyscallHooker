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
#define SECRET "TOP-SECRET"

char *read_from_remote_process(pid_t child, long addr, int len) {
    char *orig_str = (char*) malloc(len + 1);

    if (!orig_str) {
        FATAL("malloc() failed");
    }

    char *str = orig_str;
    bzero(str, len+1);

    int i = 0;
    int j = len / sizeof(long);

    // union for read data as long, then as string :)
    union u {
        long word;
        char chars[sizeof(long)];
    } data;

    while (i < j) {
        data.word = ptrace(PTRACE_PEEKDATA, child, addr + (sizeof(long) * i), NULL);
        memcpy(str, data.chars, sizeof(long));
        i++;
        str += sizeof(long);
    }

    j = len % sizeof(long);

    // check if we have more data that is not word aligned    
    if (j) {
        data.word = ptrace(PTRACE_PEEKDATA, child, addr + (sizeof(long) * i), NULL);
        memcpy(str, data.chars, j);
    }

    str[len] = '\0';
    return orig_str;
}

void filter_write_syscall(pid_t remote_pid) {
    printf("Dropping \"%s\" word for process: %d ..\n", SECRET, remote_pid);

    if (ptrace(PTRACE_ATTACH, remote_pid, NULL, NULL) == -1)
        perror("ptrace attach failed");

    waitpid(remote_pid, 0, 0);

    for (;;) {
        // enter the next syscall
        if (ptrace(PTRACE_SYSCALL, remote_pid, NULL, NULL) == -1) {
            FATAL("ptrace failed");
        }

        // wait for the tracee to enter the desired state
        if (waitpid(remote_pid, 0, 0) == -1) {
            FATAL("waitpid() failed");
        }

        // gather system call arguments
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, remote_pid, NULL, &regs) == -1) {
            FATAL("ptrace(PTRACE_GETREGS) failed");
        }

        long syscall_number = regs.orig_rax;

        if (syscall_number == SYS_write) {
            char *write_buf = read_from_remote_process(remote_pid, regs.rsi, regs.rdx);

            if (strstr(write_buf, SECRET)) {
                printf("%s detected in write() syscall !!! Dropping syscall :)\n", SECRET);

                // Drop the syscall ..
                regs.orig_rax = -1;
                ptrace(PTRACE_SETREGS, remote_pid, 0, &regs);
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: ./dropper <remote_process_pid>\n");
        exit(1);
    }

    pid_t remote_pid = atoi(argv[1]);
    filter_write_syscall(remote_pid);
}