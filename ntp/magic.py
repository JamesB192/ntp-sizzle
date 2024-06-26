# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause
"""Add ntp.h definitions... NTP definitions for the masses."""

# NTP protocol parameters.  See section 3.2.6 of the specification.
NTP_VERSION = 4  # current version number
NTP_OLDVERSION = 1  # oldest credible version: see #707
NTPv1 = 1  # Gets special treatment: see receive()
NTP_PORT = 123  # included for non-unix machines
NTP_PORTA = "123"  # or unix without /etc/services

NTP_MINPOLL    = 0       # log2 min poll interval (1 s)

# Values for peer.leap, sys_leap
LEAP_NOWARNING = 0x0  # normal, no leap second warning
LEAP_ADDSECOND = 0x1  # last minute of day has 61 seconds
LEAP_DELSECOND = 0x2  # last minute of day has 59 seconds
LEAP_NOTINSYNC = 0x3  # overload, clock is free running

# Packet Modes
MODE_UNSPEC = 0  # unspecified (old version)
MODE_ACTIVEx = 1  # symmetric active mode
MODE_PASSIVEx = 2  # symmetric passive mode
MODE_CLIENT = 3  # client mode
MODE_SERVER = 4  # server mode
MODE_BROADCASTx = 5  # broadcast mode

# These can appear in packets
MODE_CONTROL = 6  # control mode, ntpq
MODE_PRIVATEx = 7  # Dead: private mode, was ntpdc
# This is a madeup mode for broadcast client.  No longer used by ntpd.
#
# #define	MODE_BCLIENT	6	** broadcast client mode
MODE_BCLIENTX = 6  # for pylib/util.py

LEN_PKT_NOMAC = 48  # min header length

# The RFCs carefully avoid specifying this.
MAX_EXT_LEN = 4096  # maximum length of extension-field data

# Stuff for extracting things from li_vn_mode
def PKT_MODE(li_vn_mode): return        ((li_vn_mode) & 0x7)
def PKT_VERSION(li_vn_mode): return     (((li_vn_mode) >> 3) & 0x7)
def PKT_LEAP(li_vn_mode): return        (((li_vn_mode) >> 6) & 0x3)

# Stuff for putting things back into li_vn_mode in packets and vn_mode
# in ntp_monitor.c's mon_entry.
def VN_MODE(v, m): return               ((((v) & 7) << 3) | ((m) & 0x7))
def PKT_LI_VN_MODE(l, v, m): return ((((l) & 3) << 6) | VN_MODE((v), (m)))

# Event codes. Used for reporting errors/events to the control module
PEER_EVENT = 0x080  # this is a peer event

# System event codes
EVNT_UNSPEC = 0  # unspecified
EVNT_NSET = 1  # freq not set
EVNT_FSET = 2  # freq set
EVNT_SPIK = 3  # spike detect
EVNT_FREQ = 4  # freq mode
EVNT_SYNC = 5  # clock sync
EVNT_SYSRESTART = 6  # restart
EVNT_SYSFAULT = 7  # panic stop
EVNT_NOPEER = 8  # no sys peer
EVNT_ARMED = 9  # leap armed
EVNT_DISARMED = 10  # leap disarmed
EVNT_LEAP = 11  # leap event
EVNT_CLOCKRESET = 12  # clock step
EVNT_KERN = 13  # kernel event
EVNT_TAI = 14  # TAI
EVNT_LEAPVAL = 15  # stale leapsecond values

# Peer event codes
PEVNT_MOBIL = 1 | PEER_EVENT  # mobilize
PEVNT_DEMOBIL = 2 | PEER_EVENT  # demobilize
PEVNT_UNREACH = 3 | PEER_EVENT  # unreachable
PEVNT_REACH = 4 | PEER_EVENT  # reachable
PEVNT_RESTART = 5 | PEER_EVENT  # restart
PEVNT_REPLY = 6 | PEER_EVENT  # no reply
PEVNT_RATE = 7 | PEER_EVENT  # rate exceeded
PEVNT_DENY = 8 | PEER_EVENT  # access denied
PEVNT_ARMED = 9 | PEER_EVENT  # leap armed
PEVNT_NEWPEER = 10 | PEER_EVENT  # sys peer
PEVNT_CLOCK = 11 | PEER_EVENT  # clock event
PEVNT_AUTH = 12 | PEER_EVENT  # bad auth
PEVNT_POPCORN = 13 | PEER_EVENT  # popcorn

# Clock event codes
CEVNT_NOMINAL = 0  # unspecified
CEVNT_TIMEOUT = 1  # no reply
CEVNT_BADREPLY = 2  # bad format
CEVNT_FAULT = 3  # fault
CEVNT_PROP = 4  # bad signal
CEVNT_BADDATE = 5  # bad date
CEVNT_BADTIME = 6  # bad time
CEVNT_MAX = CEVNT_BADTIME


# Access flags.  Do not change or garbage-collect these, they are exposed
# through the Mode 6 protocol.
RES_IGNORE = 0x0001  # ignore packet
RES_DONTSERVE = 0x0002  # access denied
RES_DONTTRUST = 0x0004  # authentication required
RES_VERSION = 0x0008  # version mismatch
RES_NOPEERx = 0x0010  # new association denied
RES_LIMITED = 0x0020  # packet rate exceeded

RES_NOQUERY = 0x0040  # mode 6 packet denied
RES_NOMODIFY = 0x0080  # mode 6 modify denied
RES_NOTRAPx = 0x0100  # mode 6 set trap denied (not used)
RES_LPTRAPx = 0x0200  # mode 6 low priority trap (not used)

RES_KOD = 0x0400  # send kiss of death packet
RES_MSSNTP = 0x0800  # enable MS-SNTP authentication
RES_FLAKE = 0x1000  # flakeway - drop 10%
RES_NOMRULIST = 0x2000  # mode 6 mrulist denied

# RES_DEFAULT defined in /usr/include/resolv.h
RES_Default = RES_NOQUERY | RES_LIMITED
