#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program-to-run> [args...]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execv");
        return 1;
    } else {
        int status;
        int insyscall = 0;  // Variable to track if we are in a syscall
        waitpid(child, &status, 0);

        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD);

        while (1) {
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &status, 0);

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                break;
            }

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);

            if (regs.orig_rax == SYS_connect) {
                    long socklen_ptr = ptrace(PTRACE_PEEKDATA, child, regs.rdx, NULL);
                    socklen_t addrlen = regs.rdx;
                    // in such case, 
                    if (addrlen!=sizeof(struct sockaddr_in)||addrlen!=sizeof(struct sockaddr_in6)) {
                        
                    }
                    printf("Connect called with addrlen %lx\n", addrlen);
                    int fd;
                    ptrace(PTRACE_PEEKDATA, child, regs.rdi, &fd);
                    printf("Connect called with fd %d\n", fd);
                    long data[2];
                    struct sockaddr_in addr;

                     data[0] = ptrace(PTRACE_PEEKDATA, child, regs.rsi, NULL);
                     data[1] = ptrace(PTRACE_PEEKDATA, child, regs.rsi - sizeof(long), NULL);
                   
                    // printf("Data: %lx %lx\n", data[0], data[1]);

                     memcpy(&addr, data, sizeof(addr));
                    // printf("Address Family: %d (Expected AF_INET: %d)\n", addr.sin_family, AF_INET);
                    // printf("IP Address: %s\n", inet_ntoa(addr.sin_addr));

                    // ptrace(PTRACE_PEEKDATA, child, regs.rsi, &addr);
                    // printf("Address Family: %d (Expected AF_INET: %d)\n", addr.sin_family, AF_INET);
                    // printf("IP Address: %s\n", inet_ntoa(addr.sin_addr));
    // printf("Address Family: %d (Expected AF_INET: %d)\n", addr.sin_family, AF_INET);
    // printf("IP Address: %s\n", inet_ntoa(addr.sin_addr));
                    //print size of ipv6 address
                    // printf("Size of ipv6 address: %d\n", sizeof(struct sockaddr_in6));
                    if (addr.sin_family == AF_INET && addr.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                        printf("Rejecting connect call to non-loopback address\n");
                        regs.rax = -1;
                        ptrace(PTRACE_SETREGS, child, NULL, &regs);
                    }

                } else {
                    // syscall exit
                    insyscall = 0;
                }


        }
    }
    return 0;
}
