
    .file "trts.S"

#include "linux/linux-regs.h"

    .text

/*
 * -------------------------------------------------------------------------
 * extern "C" void abort(void) __attribute__(__noreturn__);
 * -------------------------------------------------------------------------
 */
DECLARE_LOCAL_FUNC abort
    ud2