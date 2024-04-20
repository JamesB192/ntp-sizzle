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

#include "ntp_machine.h"
#include "ntpd.h"
#include "ntp_io.h"
#include "ntp_fp.h"
#include "ntp_stdlib.h"
#include "ntp_syslog.h"
#include "timespecops.h"

#include "ntp_config.h"
#include "ntp_assert.h"

#include "ntp_control.h"

#include "pymodule-mac.h"

void ntpc_setprogname(char*);
bool ntpc_adj_systime(double);
bool ntpc_step_systime(double);

/* Don't include anything from OpenSSL */

const char *version = NTPSEC_VERSION_EXTENDED;
const char *progname = "libntpc";
int   SYS_TYPE = TYPE_SYS;
int  PEER_TYPE = TYPE_PEER;
int CLOCK_TYPE = TYPE_CLOCK;

/*
 * Client utility functions
 */

void
ntpc_setprogname(char *s)
{
	/*
	 * This function is only called from clients.  Therefore
	 * log to stderr rather than syslog, and suppress logfile
	 * impediments.  If we ever want finer-grained control, that
	 * will be easily implemented with additional arguments.
	 */
	syslogit = false;	/* don't log messages to syslog */
	termlogit = true;	/* duplicate to stdout/err */
	termlogit_pid = false;
	msyslog_include_timestamp = false;
	progname = strdup(s);
}

int dumbslew(int64_t s, int32_t us) {
    struct timeval step = {s, us};
    return adjtime(&step, NULL);
}

int dumbstep(int64_t s, int32_t ns) {
    struct timespec step = {s, ns};
    return clock_settime(CLOCK_REALTIME, &step);
}
