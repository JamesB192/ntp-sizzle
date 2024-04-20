# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

"""Access libntp funtions from Python."""
from __future__ import absolute_import
import ctypes
import ctypes.util
import os
import os.path
import re
import sys
import time
import ntp.control
import ntp.magic
import ntp.poly

PIVOT = 1703823396


def _fmt():
    """Produce library naming scheme."""
    if sys.platform.startswith('darwin'):
        return 'lib%s.dylib'
    if sys.platform.startswith('win32'):
        return '%s.dll'
    if sys.platform.startswith('cygwin'):
        return 'lib%s.dll'
    return 'lib%s.so'


def ntpc_version(lib):
    wrap_version = "@NTPSEC_VERSION_EXTENDED@"
    clib_version = ntp.poly.polystr(
        ctypes.c_char_p.in_dll(lib, 'version').value)
    if clib_version != wrap_version:
        sys.stderr.write("%s wrong version '%s' != '%s'\n" % (
            lib, clib_version, wrap_version))


def _importado(lib="c", hook=None):
    """Load the ntpc library or throw an OSError trying."""
    lib_paths = [         # places to look
        os.path.join(os.path.abspath(x), _fmt() % lib)
        for x in [
            os.path.dirname(os.path.realpath(ntp.__path__[0])),
            os.path.realpath("@LIBDIR@"),
            ]
        ]

    lib_path = ctypes.util.find_library(lib)
    if lib_path:
        lib_paths.append(lib_path)

    for lib_path in lib_paths:
        try:
            sys.stderr.write("INFO: try library: %s\n" % lib_path)
            lib = ctypes.CDLL(lib_path, use_errno=True)
            if callable(hook):
                hook(lib)
            return lib
        except OSError:
            pass
    raise OSError("Can't find %s library" % lib)


_ntpc = _importado('ntpc', hook=ntpc_version)
_c = _importado('c')


progname = ctypes.c_char_p.in_dll(_ntpc, 'progname')
# log_sys = ctypes.c_bool.in_dll(_ntpc, 'syslogit')
# log_term = ctypes.c_bool.in_dll(_ntpc, 'termlogit')
# log_pid = ctypes.c_bool.in_dll(_ntpc, 'termlogit_pid')
# log_time = ctypes.c_bool.in_dll(_ntpc, 'msyslog_include_timestamp')

TYPE_SYS = ctypes.c_int.in_dll(_ntpc, 'SYS_TYPE').value
TYPE_PEER = ctypes.c_int.in_dll(_ntpc, 'PEER_TYPE').value
TYPE_CLOCK = ctypes.c_int.in_dll(_ntpc, 'CLOCK_TYPE').value


def checkname(name):
    """Check if name is a valid algorithm name."""
    _ntpc.do_checkname.restype = ctypes.c_int
    mid_bytes = ntp.poly.polybytes(name)
    _ntpc.do_checkname.argtypes = [ctypes.c_char_p]
    return _ntpc.do_checkname(mid_bytes)


def mac(data, key, name):
    """Compute HMAC or CMAC from data, key, and algorithm name."""
    resultlen = ctypes.c_size_t()
    result = (ctypes.c_ubyte * 64)()
    result.value = b'\0' * 64
    _ntpc.do_mac.restype = None
    _ntpc.do_mac(ntp.poly.polybytes(name),
                 ntp.poly.polybytes(data), len(data),
                 ntp.poly.polybytes(key), len(key),
                 ctypes.byref(result), ctypes.byref(resultlen))
    return ntp.poly.polybytes(bytearray(result)[:min(resultlen.value, 20)])


def setprogname(in_string):
    """Set program name for logging purposes."""
    mid_bytes = ntp.poly.polybytes(in_string)
    _setprogname(mid_bytes)


def msyslog(level, in_string):
    """Log send a message to terminal or output."""
    mid_bytes = ntp.poly.polybytes(in_string)
    _msyslog(level, mid_bytes)


# Set return type and argument types of hidden ffi handlers
_msyslog = _ntpc.msyslog
_msyslog.restype = None
_msyslog.argtypes = [ctypes.c_int, ctypes.c_char_p]

_setprogname = _ntpc.ntpc_setprogname
_setprogname.restype = None
_setprogname.argtypes = [ctypes.c_char_p]

# Adjust system time by slewing.
adj_systime = _ntpc.ntpc_adj_systime
adj_systime.restype = ctypes.c_bool
adj_systime.argtypes = [ctypes.c_double]

# Adjust system time by stepping.
step_systime = _ntpc.ntpc_step_systime
step_systime.restype = ctypes.c_bool
step_systime.argtypes = [ctypes.c_double]

# Convert an ntp time32_t to a unix timespec near pivot time.
ntpcal_ntp_to_time = _ntpc.ntpcal_ntp_to_time
ntpcal_ntp_to_time.restype = ctypes.c_ulonglong
ntpcal_ntp_to_time.argtypes = [ctypes.c_ulong, ctypes.c_ulong]


def ihextolfp(istring):
    """Convert an ascii hex string to an l_fp."""
    pat = r" *(0[xX])?([0-9A-Fa-f]{8}).?([0-9A-Fa-f]{8})[ \n\0]*"
    hits = re.match(pat, istring)
    if not hits:
        raise ValueError("ill-formed hex date")
    l_fp = int(hits.group(2), 16)
    l_fp <<= 32
    l_fp |= int(hits.group(3), 16)
    return l_fp


def lfp_stamp_to_tspec(when, pivot=PIVOT):
    """Convert an l_fp to a unix timespec near pivot time.

    absolute (timestamp) conversion. Input is time in NTP epoch, output
    is in UN*X epoch. The NTP time stamp will be expanded around the
    pivot time p.
    """
    x = (when >> 32) & 0xffffffff
    sec = ntpcal_ntp_to_time(x, pivot)
    return [sec, (when & 0xffffffff) * 1000000000 / 4294967296]


def prettydate(in_string):
    """Convert a time stamp to something readable."""
    lfp = ihextolfp(in_string[2:])
    ts = lfp_stamp_to_tspec(lfp)
    rfc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts[0]))
    return "%08x.%08x %s.%03dZ" % (
        (lfp >> 32) & 0xffffffff,
        lfp & 0xffffffff,
        rfc, int(ts[1]/1e6))


def lfptofloat(in_string):
    """NTP l_fp to Python-style float time."""
    l_fp = ihextolfp(in_string[2:])
    tspec = lfp_stamp_to_tspec(l_fp)
    return tspec[0] + (tspec[1] / 1e9)


# --- === *** === ---


clock_codes = [
    [ntp.control.CTL_CLK_OKAY,         "clk_unspec"],
    [ntp.control.CTL_CLK_NOREPLY,      "clk_no_reply"],
    [ntp.control.CTL_CLK_BADFORMAT,    "clk_bad_format"],
    [ntp.control.CTL_CLK_FAULT,        "clk_fault"],
    [ntp.control.CTL_CLK_PROPAGATION,  "clk_bad_signal"],
    [ntp.control.CTL_CLK_BADDATE,      "clk_bad_date"],
    [ntp.control.CTL_CLK_BADTIME,      "clk_bad_time"],
    [-1,                               "clk"],
]
leap_codes = [
    [ntp.magic.LEAP_NOWARNING,       "leap_none"],
    [ntp.magic.LEAP_ADDSECOND,       "leap_add_sec"],
    [ntp.magic.LEAP_DELSECOND,       "leap_del_sec"],
    [ntp.magic.LEAP_NOTINSYNC,       "leap_alarm"],
    [-1,                             "leap"],
]
sync_codes = [
    [ntp.control.CTL_SST_TS_UNSPEC,    "sync_unspec"],
    [ntp.control.CTL_SST_TS_ATOM,      "sync_pps"],
    [ntp.control.CTL_SST_TS_LF,        "sync_lf_radio"],
    [ntp.control.CTL_SST_TS_HF,        "sync_hf_radio"],
    [ntp.control.CTL_SST_TS_UHF,       "sync_uhf_radio"],
    [ntp.control.CTL_SST_TS_LOCAL,     "sync_local"],
    [ntp.control.CTL_SST_TS_NTP,       "sync_ntp"],
    [ntp.control.CTL_SST_TS_UDPTIME,   "sync_other"],
    [ntp.control.CTL_SST_TS_WRSTWTCH,  "sync_wristwatch"],
    [ntp.control.CTL_SST_TS_TELEPHONE, "sync_telephone"],
    [-1,                               "sync"],
]
sys_codes = [
    [ntp.magic.EVNT_UNSPEC,          "unspecified"],
    [ntp.magic.EVNT_NSET,            "freq_not_set"],
    [ntp.magic.EVNT_FSET,            "freq_set"],
    [ntp.magic.EVNT_SPIK,            "spike_detect"],
    [ntp.magic.EVNT_FREQ,            "freq_mode"],
    [ntp.magic.EVNT_SYNC,            "clock_sync"],
    [ntp.magic.EVNT_SYSRESTART,      "restart"],
    [ntp.magic.EVNT_SYSFAULT,        "panic_stop"],
    [ntp.magic.EVNT_NOPEER,          "no_sys_peer"],
    [ntp.magic.EVNT_ARMED,           "leap_armed"],
    [ntp.magic.EVNT_DISARMED,        "leap_disarmed"],
    [ntp.magic.EVNT_LEAP,            "leap_event"],
    [ntp.magic.EVNT_CLOCKRESET,      "clock_step"],
    [ntp.magic.EVNT_KERN,            "kern"],
    [ntp.magic.EVNT_TAI,             "TAI"],
    [ntp.magic.EVNT_LEAPVAL,         "stale_leapsecond_values"],
    [-1,                             "evnt"],
]
select_codes = [
    [ntp.control.CTL_PST_SEL_REJECT,   "sel_reject"],
    [ntp.control.CTL_PST_SEL_SANE,     "sel_falsetick"],
    [ntp.control.CTL_PST_SEL_CORRECT,  "sel_excess"],
    [ntp.control.CTL_PST_SEL_SELCAND,  "sel_outlier"],
    [ntp.control.CTL_PST_SEL_SYNCCAND, "sel_candidate"],
    [ntp.control.CTL_PST_SEL_EXCESS,   "sel_backup"],
    [ntp.control.CTL_PST_SEL_SYSPEER,  "sel_sys.peer"],
    [ntp.control.CTL_PST_SEL_PPS,      "sel_pps.peer"],
    [-1,                               "sel"],
]
peer_codes = [
    [ntp.magic.PEVNT_MOBIL,    "mobilize"],
    [ntp.magic.PEVNT_DEMOBIL,  "demobilize"],
    [ntp.magic.PEVNT_UNREACH,  "unreachable"],
    [ntp.magic.PEVNT_REACH,    "reachable"],
    [ntp.magic.PEVNT_RESTART,  "restart"],
    [ntp.magic.PEVNT_REPLY,    "no_reply"],
    [ntp.magic.PEVNT_RATE,     "rate_exceeded"],
    [ntp.magic.PEVNT_DENY,     "access_denied"],
    [ntp.magic.PEVNT_ARMED,    "leap_armed"],
    [ntp.magic.PEVNT_NEWPEER,  "sys_peer"],
    [ntp.magic.PEVNT_CLOCK,    "clock_event"],
    [ntp.magic.PEVNT_AUTH,     "bad_auth"],
    [ntp.magic.PEVNT_POPCORN,  "popcorn"],
    [-1,                       "pevnt"],
]
peer_st_bits = [
    [ntp.control.CTL_PST_CONFIG,               "conf"],
    [ntp.control.CTL_PST_AUTHENABLE,           "authenb"],
    [ntp.control.CTL_PST_AUTHENTIC,            "auth"],
    [ntp.control.CTL_PST_REACH,                "reach"],
    [ntp.control.CTL_PST_BCAST,                "bcast"],
]


def getcode(tab, key):
    try:
        tab2 = [x[0] for x in tab]
        key2 = tab2.index(key)
        return tab[key2][1]
    except ValueError:
        return tab[-1][1] + '_' + str(key)


def sys_status(st):
    return [
        getcode(leap_codes, (st >> 14) & 0x3),
        getcode(sync_codes, (st >> 8) & 0x3f),
        getevents((st >> 4) & 0xf),
        getcode(sys_codes, st & 0xf),
    ]


def peer_status(st):
    pst = 0xff & (st >> 8)
    ret = [
        decode_bitflags(pst, ", ", peer_st_bits),
        getcode(select_codes, pst & 0x7),
        getevents((st >> 4) & 0xf),
    ]
    if (st & ~ntp.magic.PEER_EVENT) != ntp.magic.EVNT_UNSPEC:
        ret.append(getcode(peer_codes, 128 + (st & 0xf)))  # FIXME
    return ret


def clock_status(st):
    return [
        getevents((st >> 4) & 0xf),
        getcode(clock_codes, st & 0xf),
    ]


def statustoa(typeof, st):
    return ', '.join(typical[typeof](st)) if typeof in typical else ""


def getevents(cnt):
    """getevents - return a descriptive string for the event count."""
    if cnt == 0:
        return "no events"
    if cnt == 1:
        return "1 event"
    return str(cnt) + " events"


def decode_bitflags(bits, sep2, tab):
    pieces = []
    for row in tab:
        if row[0] & bits:
            pieces.append(row[1])
    return sep2.join(pieces)


typical = {
    ntp.control.TYPE_CLOCK: clock_status,
    ntp.control.TYPE_PEER: peer_status,
    ntp.control.TYPE_SYS: sys_status,
}
