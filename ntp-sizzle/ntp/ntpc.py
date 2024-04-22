# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

"""Access libntp funtions from Python."""
from __future__ import absolute_import
import re
import time
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.cmac
import ntp.control
import ntp.magic
import ntp.poly
import ntp.c as c

PIVOT = 1703823396
MILLION = int(1e6)
BILLION = int(1e9)

TYPE_SYS   = 1
TYPE_PEER  = 2
TYPE_CLOCK = 3


def setprogname(_):
    pass


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
    sec = c.lfp2timet(x, pivot)
    return [sec, (when & 0xffffffff) * BILLION / 4294967296]


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
        ret.append(getcode(peer_codes, 128 | (st & 0xf)))
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


def lfp_stamp_to_tval(when, pivot=PIVOT):
    """Convert an l_fp to a unix timeval near pivot time.

    absolute (timeval) conversion. Input is time in NTP epoch, output
    is in UN*X epoch. The NTP time stamp will be expanded around the
    pivot time.
    """
    x = (when >> 32) & 0xffffffff
    sec = c.lfp2timet(x, pivot)
    return [sec, (when & 0xffffffff) * MILLION / 4294967296]


def step_systime(bigstep, pivot=PIVOT):
    # Adjust system time by stepping.
    tval = lfp_stamp_to_tval(bigstep, pivot)
    retval = c.step(*tval)
    if retval == 0:
        return True
    return False


def adj_systime(bigstep, pivot=PIVOT):
    # Adjust system time by slewing.
    tspec = lfp_stamp_to_tspec(bigstep, pivot)
    retval = c.slew(*tspec)
    if retval == 0:
        return True
    return False


# --- === *** === ---

hashes = {
    "md5": cryptography.hazmat.primitives.hashes.MD5(),
    "sha1": cryptography.hazmat.primitives.hashes.SHA1(),
    "sm3": cryptography.hazmat.primitives.hashes.SM3(),
    "shake128": cryptography.hazmat.primitives.hashes.SHAKE128(16),
    "shake256": cryptography.hazmat.primitives.hashes.SHAKE256(32),
    "sha3-512": cryptography.hazmat.primitives.hashes.SHA3_512(),
    "sha3-384": cryptography.hazmat.primitives.hashes.SHA3_384(),
    "sha3-256": cryptography.hazmat.primitives.hashes.SHA3_256(),
    "sha3-224": cryptography.hazmat.primitives.hashes.SHA3_224(),
    "blake2s256": cryptography.hazmat.primitives.hashes.BLAKE2s(32),
    "blake2b512": cryptography.hazmat.primitives.hashes.BLAKE2b(64),
    "sha512_256": cryptography.hazmat.primitives.hashes.SHA512_256(),
    "sha512_224": cryptography.hazmat.primitives.hashes.SHA512_224(),
    "sha512": cryptography.hazmat.primitives.hashes.SHA512(),
    "sha384": cryptography.hazmat.primitives.hashes.SHA384(),
    "sha256": cryptography.hazmat.primitives.hashes.SHA256(),
    "sha224": cryptography.hazmat.primitives.hashes.SHA224(),
    }

algorithms = {
    "aes": cryptography.hazmat.primitives.ciphers.algorithms.AES,
    "aes128": cryptography.hazmat.primitives.ciphers.algorithms.AES128,
    "aes192": cryptography.hazmat.primitives.ciphers.algorithms.AES,
    "aes256": cryptography.hazmat.primitives.ciphers.algorithms.AES256,
    "camellia128": cryptography.hazmat.primitives.ciphers.algorithms.Camellia,
    "camellia192": cryptography.hazmat.primitives.ciphers.algorithms.Camellia,
    "camellia256": cryptography.hazmat.primitives.ciphers.algorithms.Camellia,
    "sm4": cryptography.hazmat.primitives.ciphers.algorithms.SM4,
    }


def checkname(name):
    """Check if name is a valid algorithm name."""
    if name.lower() in hashes:
        return True
    return name.lower() in algorithms


def mac(data, key, name):
    """Compute HMAC or CMAC from data, key, and algorithm name."""
    lname = name.lower()
    if lname in hashes:
        digest = cryptography.hazmat.primitives.hashes.Hash(hashes[lname])
        digest.update(key)
        digest.update(data)
        return digest.finalize()[:20]
    elif lname in algorithms:
        work = cryptography.hazmat.primitives.cmac.CMAC(algorithms[lname](ntp.poly.polybytes(key)))
        work.update(ntp.poly.polybytes(data))
        return work.finalize()[:20]
    return b''
