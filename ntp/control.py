# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause
"""Add ntp_control.h definitions related to NTP mode 6 control messages."""
# mode 6 messages are defined in RFC 9327
#  Control Messages Protocol for Use with Network Time Protocol Version 4
#  https://www.rfc-editor.org/rfc/rfc9327.pdf


# The attribute after this structure is a gcc/clang extension that forces
# the beginning of a structure instance to be 32-bit aligned.  Without this
# attempting to compile on a 32-bit host may throw warnings or errors when
# a pointer to this structure is passed to authdecrypt/authencrypt, both of
# which expect to be able to treat the structure as an array of uint32_t
# elements.  Ideally, we'd get rid of that nasty type punning. */

# Length of the control header, in octets
CTL_MAX_DATA_LEN = 468  # = (offsetof(struct ntp_control, data))

# Decoding for the r_m_e_op field
CTL_RESPONSE = 0x80
CTL_ERROR = 0x40
CTL_MORE = 0x20
CTL_OP_MASK = 0x1F

# Opcodes
CTL_OP_UNSPEC = 0  # unspeciffied
CTL_OP_READSTAT = 1  # read status
CTL_OP_READVAR = 2  # read variables
CTL_OP_WRITEVAR = 3  # write variables
CTL_OP_READCLOCK = 4  # read clock variables
CTL_OP_WRITECLOCK = 5  # write clock variables
# #def	CTL_OP_SETTRAP		6	** set trap address (unused)
# #def	CTL_OP_ASYNCMSG		7	** trap message (unused)
CTL_OP_CONFIGURE = 8  # runtime configuration
# #def	CTL_OP_EXCONFIG		9	**  export config to file (unused)
CTL_OP_READ_MRU = 10  # retrieve MRU (mrulist)
CTL_OP_READ_ORDLIST_A = 11  # ordered list req. auth.
CTL_OP_REQ_NONCE = 12  # request a client nonce
# #def	CTL_OP_UNSETTRAP	31	** unset trap (unused)

# {En,De}coding of the system status word
CTL_SST_TS_UNSPEC = 0  # unspec
CTL_SST_TS_ATOM = 1  # pps
CTL_SST_TS_LF = 2  # lf radio
CTL_SST_TS_HF = 3  # hf radio
CTL_SST_TS_UHF = 4  # uhf radio
CTL_SST_TS_LOCAL = 5  # local
CTL_SST_TS_NTP = 6  # ntp
CTL_SST_TS_UDPTIME = 7  # other
CTL_SST_TS_WRSTWTCH = 8  # wristwatch
CTL_SST_TS_TELEPHONE = 9  # telephone

CTL_SYS_MAXEVENTS = 15

# {En,De}coding of the peer status word
CTL_PST_CONFIG = 0x80
CTL_PST_AUTHENABLE = 0x40
CTL_PST_AUTHENTIC = 0x20
CTL_PST_REACH = 0x10
CTL_PST_BCAST = 0x08

CTL_PST_SEL_REJECT = 0  #   reject
CTL_PST_SEL_SANE = 1  # x falsetick
CTL_PST_SEL_CORRECT = 2  # . excess
CTL_PST_SEL_SELCAND = 3  # - outlier
CTL_PST_SEL_SYNCCAND = 4  # + candidate
CTL_PST_SEL_EXCESS = 5  # # backup
CTL_PST_SEL_SYSPEER = 6  # * sys.peer
CTL_PST_SEL_PPS = 7  # o pps.peer

CTL_PEER_MAXEVENTS = 15

def CTL_PEER_STATUS(status, nevnt, evnt): return \
                ((((status)<<8) & 0xff00) | \
                (((nevnt)<<4) & 0x00f0) | \
                ((evnt) & 0x000f))

def CTL_PEER_STATVAL(status): return(((status)>>8) & 0xff)
def CTL_PEER_NEVNT(status): return      (((status)>>4) & 0xf)
def CTL_PEER_EVENT(status): return      ((status) & 0xf)

# {En,De}coding of the clock status word
CTL_CLK_OKAY = 0
CTL_CLK_NOREPLY = 1
CTL_CLK_BADFORMAT = 2
CTL_CLK_FAULT = 3
CTL_CLK_PROPAGATION = 4
CTL_CLK_BADDATE = 5
CTL_CLK_BADTIME = 6

# Error code responses returned when the E bit is set.
CERR_UNSPEC = 0
CERR_PERMISSION = 1
CERR_BADFMT = 2
CERR_BADOP = 3
CERR_BADASSOC = 4
CERR_UNKNOWNVAR = 5
CERR_BADVALUE = 6
CERR_RESTRICT = 7

CERR_NORESOURCE = CERR_PERMISSION  # wish there was a different code


# Types of things we may deal with
# shared between ntpq and library
TYPE_SYS = 1
TYPE_PEER = 2
TYPE_CLOCK = 3

# IFSTATS_FIELDS is the number of fields ntpd supplies for each ifstats
# row.  Similarly RESLIST_FIELDS for reslist.
IFSTATS_FIELDS = 12
RESLIST_FIELDS = 4

# To prevent replay attacks, MRU list nonces age out. Time is in seconds.
#
# Don't change this value casually.  Lengthening it might extend an
# attack window for DDoS amplification.  Shortening it might make your
# server (or client) incompatible with older versions.
NONCE_TIMEOUT = 16
