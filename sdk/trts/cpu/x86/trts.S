
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

#elif defined(__aarch64__)

DECLARE_LOCAL_FUNC abort
	ADD W0, W1, W2

#else

#wrong arch
#endif
