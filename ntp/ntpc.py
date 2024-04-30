# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

"""Access libntp funtions from Python."""
from __future__ import absolute_import
import ctypes
import ctypes.util
import errno
import os
import os.path
import sys
from ntp import control, magic
import ntp.poly

LIB = "ntpc"


def _fmt():
    """Produce library naming scheme."""
    if sys.platform.startswith("darwin"):
        return "lib%s.dylib"
    if sys.platform.startswith("win32"):
        return "%s.dll"
    if sys.platform.startswith("cygwin"):
        return "lib%s.dll"
    return "lib%s.so"


def _importado():
    """Load the ntpc library or throw an OSError trying."""
    ntpc_paths = []  # places to look

    j = __file__.split(os.sep)[:-1]
    ntpc_paths.append(os.sep.join(j + [_fmt() % LIB]))

    ntpc_path = ctypes.util.find_library(LIB)
    if ntpc_path:
        ntpc_paths.append(ntpc_path)

    return _dlo(ntpc_paths)


def _dlo(paths):
    """Try opening library from a list."""
    for ntpc_path in paths:
        try:
            lib = ctypes.CDLL(ntpc_path, use_errno=True)
            wrap_version = "@NTPSEC_VERSION_EXTENDED@"
            clib_version = ntp.poly.polystr(
                ctypes.c_char_p.in_dll(lib, "version").value
            )
            if clib_version != wrap_version:
                sys.stderr.write(
                    "ntp.ntpc wrong version '%s' != '%s'\n"
                    % (clib_version, wrap_version)
                )
            return lib
        except OSError:
            pass
    raise OSError("Can't find %s library" % LIB)


_ntpc = _importado()
progname = ctypes.c_char_p.in_dll(_ntpc, "progname")
# log_sys = ctypes.c_bool.in_dll(_ntpc, 'syslogit')
# log_term = ctypes.c_bool.in_dll(_ntpc, 'termlogit')
# log_pid = ctypes.c_bool.in_dll(_ntpc, 'termlogit_pid')
# log_time = ctypes.c_bool.in_dll(_ntpc, 'msyslog_include_timestamp')

TYPE_SYS = ctypes.c_int.in_dll(_ntpc, "SYS_TYPE").value
TYPE_PEER = ctypes.c_int.in_dll(_ntpc, "PEER_TYPE").value
TYPE_CLOCK = ctypes.c_int.in_dll(_ntpc, "CLOCK_TYPE").value


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
    result.value = b"\0" * 64
    _ntpc.do_mac.restype = None
    _ntpc.do_mac(
        ntp.poly.polybytes(name),
        ntp.poly.polybytes(data),
        len(data),
        ntp.poly.polybytes(key),
        len(key),
        ctypes.byref(result),
        ctypes.byref(resultlen),
    )
    return ntp.poly.polybytes(
        bytearray(result)[: min(resultlen.value, 20)]
    )


def setprogname(in_string):
    """Set program name for logging purposes."""
    mid_bytes = ntp.poly.polybytes(in_string)
    _setprogname(mid_bytes)


def _lfp_wrap(callback, in_string):
    """NTP l_fp to other Python-style format."""
    mid_bytes = ntp.poly.polybytes(in_string)
    out_value = callback(mid_bytes)
    err = ctypes.get_errno()
    if err == errno.EINVAL:
        raise ValueError("ill-formed hex date")
    return out_value


def prettydate(in_string):
    """Convert a time stamp to something readable."""
    mid_str = _lfp_wrap(_prettydate, in_string)
    return ntp.poly.polystr(mid_str)


def lfptofloat(in_string):
    """NTP l_fp to Python-style float time."""
    return _lfp_wrap(_lfptofloat, in_string)


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

_prettydate = _ntpc.ntpc_prettydate
_prettydate.restype = ctypes.c_char_p
_prettydate.argtypes = [ctypes.c_char_p]

_lfptofloat = _ntpc.ntpc_lfptofloat
_lfptofloat.restype = ctypes.c_double
_lfptofloat.argtypes = [ctypes.c_char_p]

# Status string display from peer status word.
_statustoa = _ntpc.statustoa
_statustoa.restype = ctypes.c_char_p
_statustoa.argtypes = [ctypes.c_int, ctypes.c_int]

# Adjust system time by slewing.
adj_systime = _ntpc.ntpc_adj_systime
adj_systime.restype = ctypes.c_bool
adj_systime.argtypes = [ctypes.c_double]

# Adjust system time by stepping.
step_systime = _ntpc.ntpc_step_systime
step_systime.restype = ctypes.c_bool
step_systime.argtypes = [ctypes.c_double]


# ---   ===   ***   ===   ---

clock_codes = [
    [control.CTL_CLK_OKAY, "clk_unspec"],
    [control.CTL_CLK_NOREPLY, "clk_no_reply"],
    [control.CTL_CLK_BADFORMAT, "clk_bad_format"],
    [control.CTL_CLK_FAULT, "clk_fault"],
    [control.CTL_CLK_PROPAGATION, "clk_bad_signal"],
    [control.CTL_CLK_BADDATE, "clk_bad_date"],
    [control.CTL_CLK_BADTIME, "clk_bad_time"],
    [-1, "clk"],
]
leap_codes = [
    [magic.LEAP_NOWARNING, "leap_none"],
    [magic.LEAP_ADDSECOND, "leap_add_sec"],
    [magic.LEAP_DELSECOND, "leap_del_sec"],
    [magic.LEAP_NOTINSYNC, "leap_alarm"],
    [-1, "leap"],
]
sync_codes = [
    [control.CTL_SST_TS_UNSPEC, "sync_unspec"],
    [control.CTL_SST_TS_ATOM, "sync_pps"],
    [control.CTL_SST_TS_LF, "sync_lf_radio"],
    [control.CTL_SST_TS_HF, "sync_hf_radio"],
    [control.CTL_SST_TS_UHF, "sync_uhf_radio"],
    [control.CTL_SST_TS_LOCAL, "sync_local"],
    [control.CTL_SST_TS_NTP, "sync_ntp"],
    [control.CTL_SST_TS_UDPTIME, "sync_other"],
    [control.CTL_SST_TS_WRSTWTCH, "sync_wristwatch"],
    [control.CTL_SST_TS_TELEPHONE, "sync_telephone"],
    [-1, "sync"],
]
sys_codes = [
    [magic.EVNT_UNSPEC, "unspecified"],
    [magic.EVNT_NSET, "freq_not_set"],
    [magic.EVNT_FSET, "freq_set"],
    [magic.EVNT_SPIK, "spike_detect"],
    [magic.EVNT_FREQ, "freq_mode"],
    [magic.EVNT_SYNC, "clock_sync"],
    [magic.EVNT_SYSRESTART, "restart"],
    [magic.EVNT_SYSFAULT, "panic_stop"],
    [magic.EVNT_NOPEER, "no_sys_peer"],
    [magic.EVNT_ARMED, "leap_armed"],
    [magic.EVNT_DISARMED, "leap_disarmed"],
    [magic.EVNT_LEAP, "leap_event"],
    [magic.EVNT_CLOCKRESET, "clock_step"],
    [magic.EVNT_KERN, "kern"],
    [magic.EVNT_TAI, "TAI"],
    [magic.EVNT_LEAPVAL, "stale_leapsecond_values"],
    [-1, "evnt"],
]
select_codes = [
    [control.CTL_PST_SEL_REJECT, "sel_reject"],
    [control.CTL_PST_SEL_SANE, "sel_falsetick"],
    [control.CTL_PST_SEL_CORRECT, "sel_excess"],
    [control.CTL_PST_SEL_SELCAND, "sel_outlier"],
    [control.CTL_PST_SEL_SYNCCAND, "sel_candidate"],
    [control.CTL_PST_SEL_EXCESS, "sel_backup"],
    [control.CTL_PST_SEL_SYSPEER, "sel_sys.peer"],
    [control.CTL_PST_SEL_PPS, "sel_pps.peer"],
    [-1, "sel"],
]
peer_codes = [
    [magic.PEVNT_MOBIL, "mobilize"],
    [magic.PEVNT_DEMOBIL, "demobilize"],
    [magic.PEVNT_UNREACH, "unreachable"],
    [magic.PEVNT_REACH, "reachable"],
    [magic.PEVNT_RESTART, "restart"],
    [magic.PEVNT_REPLY, "no_reply"],
    [magic.PEVNT_RATE, "rate_exceeded"],
    [magic.PEVNT_DENY, "access_denied"],
    [magic.PEVNT_ARMED, "leap_armed"],
    [magic.PEVNT_NEWPEER, "sys_peer"],
    [magic.PEVNT_CLOCK, "clock_event"],
    [magic.PEVNT_AUTH, "bad_auth"],
    [magic.PEVNT_POPCORN, "popcorn"],
    [-1, "pevnt"],
]
peer_st_bits = [
    [control.CTL_PST_CONFIG, "conf"],
    [control.CTL_PST_AUTHENABLE, "authenb"],
    [control.CTL_PST_AUTHENTIC, "auth"],
    [control.CTL_PST_REACH, "reach"],
    [control.CTL_PST_BCAST, "bcast"],
]


def getcode(table, key):
    """Interpet a code table to report a code there or synth."""
    try:
        index = [x[0] for x in table]
        key2 = index.index(key)
        return table[key2][1]
    except ValueError:
        return table[-1][1] + "_" + str(key)


def sys_status(status):
    """Report the system status string bits."""
    return [
        getcode(leap_codes, (status >> 14) & 0x3),
        getcode(sync_codes, (status >> 8) & 0x3F),
        getevents((status >> 4) & 0xF),
        getcode(sys_codes, status & 0xF),
    ]


def peer_status(status):
    """Report the peer status string bits."""
    pst = 0xFF & (status >> 8)
    ret = [
        decode_bitflags(pst, ", ", peer_st_bits),
        getcode(select_codes, pst & 0x7),
        getevents((status >> 4) & 0xF),
    ]
    if (status & ~magic.PEER_EVENT) != magic.EVNT_UNSPEC:
        ret.append(getcode(peer_codes, 128 | (status & 0xF)))
    return ret


def clock_status(status):
    """Report the reference clock status string bits."""
    return [
        getevents((status >> 4) & 0xF),
        getcode(clock_codes, status & 0xF),
    ]


def statustoa(typeof, status):
    """Return the status string from a given type and status word(?)."""
    return (
        ", ".join(typical[typeof](status)) if typeof in typical else ""
    )


def getevents(count):
    """getevents - return a descriptive string for the event count."""
    if count == 0:
        return "no events"
    if count == 1:
        return "1 event"
    return str(count) + " events"


def decode_bitflags(bits, sep2, tab):
    """Return a string with expanded bit-vectors; This is not snprintb."""
    pieces = []
    for row in tab:
        if row[0] & bits:
            pieces.append(row[1])
    return sep2.join(pieces)


typical = {
    control.TYPE_CLOCK: clock_status,
    control.TYPE_PEER: peer_status,
    control.TYPE_SYS: sys_status,
}
