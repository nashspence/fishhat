/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Nash Spence
 * Linux x86-64 static entry: no libc, loader, shell or environment startup.
 */
#include "targets.h"

_Static_assert(sizeof(unsigned long) == 8, "x86-64 required");
_Static_assert(sizeof(unsigned int) == 4, "Linux credential ABI required");

__asm__(".global _start\n"
        ".text\n"
        "_start:\n"
        "mov %rsp, %rdi\n"
        "andq $-16, %rsp\n"
        "call protected_launch\n"
        "ud2\n");

static long kernel(long number, long a, long b, long c, long d, long e, long f)
{
    register long fourth __asm__("r10") = d;
    register long fifth __asm__("r8") = e;
    register long sixth __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "+a"(number)
                     : "D"(a), "S"(b), "d"(c),
                       "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "memory");
    return number;
}

__attribute__((noreturn)) static void refuse(int unsupported)
{
    static const char context[] = "Unsupported invocation context\n";
    static const char unavailable[] = "Protected command unavailable\n";
    kernel(1, 2, (long)(unsupported ? context : unavailable),
           unsupported ? sizeof(context) - 1 : sizeof(unavailable) - 1, 0, 0, 0);
    kernel(60, unsupported ? 126 : 127, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

__attribute__((noreturn)) void protected_launch(unsigned long *initial)
{
    unsigned int uids[3] = {0}, gids[3] = {0};
    struct { unsigned int version; int pid; } header = {0x20080522, 0};
    struct { unsigned int effective, permitted, inheritable; } capabilities[2] = {{0}};
    unsigned long argc = initial[0];
    char **argv = (char **)(initial + 1);
    unsigned long *auxiliary = (unsigned long *)(argv + argc + 1);
    char **forwarded;
    char *environment[] = {"LANG=C.UTF-8", "LC_ALL=C.UTF-8", (void *)0};
    long memory;

    if (kernel(118, (long)&uids[0], (long)&uids[1], (long)&uids[2], 0, 0, 0)
        || kernel(120, (long)&gids[0], (long)&gids[1], (long)&gids[2], 0, 0, 0)
        || kernel(125, (long)&header, (long)capabilities, 0, 0, 0, 0))
        refuse(1);
    if (uids[0] != uids[1] || uids[0] != uids[2]
        || gids[0] != gids[1] || gids[0] != gids[2])
        refuse(1);
    if (uids[0] && (capabilities[0].effective | capabilities[0].permitted
                   | capabilities[0].inheritable | capabilities[1].effective
                   | capabilities[1].permitted | capabilities[1].inheritable))
        refuse(1);

    /* The kernel supplies this initial stack. Ignore environment values, and
     * reject secure-execution contexts before executing any other program. */
    while (*auxiliary)
        auxiliary++;
    auxiliary++;
    while (auxiliary[0]) {
        if (auxiliary[0] == 23 && auxiliary[1])
            refuse(1);
        auxiliary += 2;
    }

    if (!argc || argc > (~0UL / sizeof(char *)) - 5)
        refuse(0);
    memory = kernel(9, 0, (argc + 5) * sizeof(char *), 3, 0x22, -1, 0);
    if ((unsigned long)memory >= (unsigned long)-4095)
        refuse(0);
    forwarded = (char **)memory;
    forwarded[0] = OWNER_INTERPRETER;
    forwarded[1] = "-I";
    forwarded[2] = "-S";
    forwarded[3] = "-B";
    forwarded[4] = OWNER_PROGRAM;
    for (unsigned long index = 1; index < argc; index++)
        forwarded[index + 4] = argv[index];
    forwarded[argc + 4] = (void *)0;

    /* Inherit the principal, cwd and explicit stdin/out/err. Do not pass other
     * inherited descriptors or ambient environment to the selected runtime. */
    if (kernel(436, 3, 0xffffffffUL, 0, 0, 0, 0))
        refuse(0);
    kernel(95, 077, 0, 0, 0, 0, 0);
    kernel(59, (long)OWNER_INTERPRETER, (long)forwarded, (long)environment, 0, 0, 0);
    refuse(0);
}
