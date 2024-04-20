/*
 * Copyright the NTPsec project contributors
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Python binding for selected libntp library functions
 */

/* This include has to come early or we get warnings from redefining
 * _POSIX_C_SOURCE and _XOPEN_SOURCE on some systems.
 */
#include "config.h"

#include "ntp.h"
#include "ntp_control.h"

int dumbslew(int64_t s, int32_t us);
int dumbstep(int64_t s, int32_t ns);
time64_t ntpcal_ntp_to_time(uint32_t ntp, time_t pivot);

/* Don't include anything from OpenSSL */

const char *version = NTPSEC_VERSION_EXTENDED;
const char *progname = "libntpc";
int   SYS_TYPE = TYPE_SYS;
int  PEER_TYPE = TYPE_PEER;
int CLOCK_TYPE = TYPE_CLOCK;

/*
 * Client utility functions
 */

int dumbslew(int64_t s, int32_t us) {
    struct timeval step = {s, us};
    return adjtime(&step, NULL);
}

int dumbstep(int64_t s, int32_t ns) {
    struct timespec step = {s, ns};
    return clock_settime(CLOCK_REALTIME, &step);
}

/* Convert a timestamp in NTP scale to a 64bit seconds value in the UN*X
 * scale with proper epoch unfolding around a given pivot or the current
 * system time. This function happily accepts negative pivot values as
 * timestamps before 1970-01-01, so be aware of possible trouble on
 * platforms with 32bit 'time_t'!
 *
 * This is also a periodic extension, but since the cycle is 2^32 and
 * the shift is 2^31, we can do some *very* fast math without explicit
 * divisions.
 */
time64_t ntpcal_ntp_to_time(uint32_t ntp, time_t pivot) {
    time64_t res;

    settime64s(res, pivot);
    settime64u(res, time64u(res)-0x80000000);	 // unshift of half range
    ntp	-= (uint32_t)2208988800;		 // warp into UN*X domain
    ntp	-= time64lo(res);			 // cycle difference
    settime64u(res, time64u(res)+(uint64_t)ntp); // get expanded time

    return res;
}
