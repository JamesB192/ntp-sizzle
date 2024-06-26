# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

"""Access libntp funtions from Python."""
from __future__ import absolute_import
import math
import re
import time
from cryptography.hazmat.primitives import ciphers, cmac, hashes
from . import c, control, magic, poly
from .control import TYPE_CLOCK, TYPE_PEER, TYPE_SYS
PIVOT = 1712793600
MILLION = int(1e6)
BILLION = int(1e9)
UINT32MAX = (1 << 32) -1

def setprogname(_):
    """Take the name of the script being called and do nothing."""
    return None


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


def prettydate(in_string):
    """Convert a time stamp to something readable."""
    lfp = ihextolfp(in_string[2:])
    timeval = lfp_stamp_to_tval(lfp)
    rfc = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(timeval[0]))
    return "%08x.%08x %s.%03dZ" % (
        (lfp >> 32) & UINT32MAX,
        lfp & UINT32MAX,
        rfc,
        int(timeval[1] / 1e3),
    )


def lfptofloat(in_string):
    """NTP l_fp to Python-style float time."""
    l_fp = ihextolfp(in_string[2:])
    tval = lfp_stamp_to_tval(l_fp)
    frac = (l_fp & UINT32MAX) / float(1 << 32)
    return frac + tval[0]


def lfp_stamp_to_tval(when, pivot=PIVOT):
    """Convert an l_fp to a unix timeval near pivot time.

    absolute (timeval) conversion. Input is time in NTP epoch, output
    is in UN*X epoch. The NTP time stamp will be expanded around the
    pivot time.
    """
    l_fps = (when >> 32) & UINT32MAX
    sec = c.lfp2timet(l_fps, pivot)
    return [sec, (((when & UINT32MAX) * MILLION) >> 32) & UINT32MAX]


def ftotval(float_value):
    """Convert float value to `struct timeval`(ish) value."""
    parts = math.modf(float_value)
    if parts[0] < 0:
        parts = (parts[0] + 1, parts[1] - 1)
    return (parts[0] * MILLION, parts[1])


def step_systime(bigstep):
    """Adjust system time by stepping."""
    tval = ftotval(bigstep)
    retval = c.step(*tval)
    if retval == 0:
        return True
    return False


def adj_systime(adjust_by):
    """Adjust system time by slewing."""
    tval = ftotval(adjust_by)
    retval = c.slew(*tval)
    if retval == 0:
        return True
    return False


# ---   ===   ***   ===   ---

hash_list = {
    "md5": hashes.MD5(),
    "sha1": hashes.SHA1(),
    "sm3": hashes.SM3(),
    "shake128": hashes.SHAKE128(16),
    "shake256": hashes.SHAKE256(32),
    "sha3-512": hashes.SHA3_512(),
    "sha3-384": hashes.SHA3_384(),
    "sha3-256": hashes.SHA3_256(),
    "sha3-224": hashes.SHA3_224(),
    "blake2s256": hashes.BLAKE2s(32),
    "blake2b512": hashes.BLAKE2b(64),
    "sha512_256": hashes.SHA512_256(),
    "sha512_224": hashes.SHA512_224(),
    "sha512": hashes.SHA512(),
    "sha384": hashes.SHA384(),
    "sha256": hashes.SHA256(),
    "sha224": hashes.SHA224(),
}

algorithms = {
    "aes": ciphers.algorithms.AES,
    "aes-128": ciphers.algorithms.AES128,
    "aes-192": ciphers.algorithms.AES,
    "aes-256": ciphers.algorithms.AES256,
    "camellia-128": ciphers.algorithms.Camellia,
    "camellia-192": ciphers.algorithms.Camellia,
    "camellia-256": ciphers.algorithms.Camellia,
    "sm4": ciphers.algorithms.SM4,
}


def checkname(name):
    """Check if name is a valid algorithm name."""
    if name.lower() in hash_list:
        return True
    return name.lower() in algorithms


def mac(data, key, name):
    """Compute HMAC or CMAC from data, key, and algorithm name."""
    lname = name.lower()
    if lname in hash_list:
        digest = hashes.Hash(hash_list[lname])
        digest.update(key)
        digest.update(data)
        return digest.finalize()[:20]
    if lname in algorithms:
        work = cmac.CMAC(algorithms[lname](poly.polybytes(key)))
        work.update(poly.polybytes(data))
        return work.finalize()[:20]
    return None


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
    TYPE_CLOCK: clock_status,
    TYPE_PEER: peer_status,
    TYPE_SYS: sys_status,
}
