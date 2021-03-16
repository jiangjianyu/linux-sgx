
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include "syscall.h"
#include "assert.h"

extern void* ssbrk(intptr_t n);

long __esyscall(long sysid, ...) {
    va_list args;         
    long ret = 0;
    void* mapp_addr;
    size_t size;
    int mode;
    va_start(args, sysid);

    switch (sysid) {
        case SYS_brk: 
            ret = (long) ssbrk(va_arg(args, intptr_t));
            break;
        case SYS_mmap:
            // mapped_addr should be align
            mapp_addr = va_arg(args, void*);
            size = va_arg(args, size_t);
            if (mapp_addr == NULL) {
                ret = (long)ssbrk((intptr_t)size);
            } else {
                ret = (long)mapp_addr;
            }
            break;
        case SYS_mprotect:
            mapp_addr = va_arg(args, void*);
            size = va_arg(args, size_t);
            mode = va_arg(args, int);
            if ((mode & ~(PROT_READ | PROT_WRITE))) {
                ret = -1;
            }
            break;
        case SYS_munmap:
            // dummy implementations.
            break;
        default: asm("ud2\n"); break;
    }
    va_end(args);
    return ret;
}