/*
 * cabs() wrapper for hypot().
 *
 * Written by J.T. Conklin, <jtc@wimsey.com>
 * Placed into the Public Domain, 1994.
 */

#include "cdefs-compat.h"
//__FBSDID("$FreeBSD: src/lib/msun/src/w_cabs.c,v 1.7 2008/03/30 20:03:06 das Exp $");

#include <complex.h>
#include <float.h>
#include <openlibm.h>
#include "math_private.h"

DLLEXPORT double
cabs(double complex z)
{
	return hypot(creal(z), cimag(z));
}

#if LDBL_MANT_DIG == 53
__weak_reference(cabs, cabsl);
#endif
