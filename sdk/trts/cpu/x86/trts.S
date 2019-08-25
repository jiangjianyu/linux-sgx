
    .file "trts.S"

#include "linux/linux-regs.h"

    .text

/*
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */

#if defined(__x86_64__)

DECLARE_LOCAL_FUNC abort
    ud2

#elif defined(__arm__)

DECLARE_LOCAL_FUNC abort

#else

#endif