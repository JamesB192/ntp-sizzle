# -*- coding: utf-8 -*-
# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

"""Authentication and MAC functions."""
from __future__ import absolute_import
import hmac
import struct
from cryptography.hazmat.primitives import ciphers, cmac, hashes
from ntp import magic, ntpc, poly, util

KEYID_LENGTH = 4
digests = {
    "md5": hashes.MD5(),
    "sha1": hashes.SHA1(),
    "sha-1": hashes.SHA1(),
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
    if name.lower() in digests:
        return True
    return name.lower() in algorithms


def mac(data, key, name):
    """Compute HMAC or CMAC from data, key, and algorithm name."""
    lname = name.lower()
    if lname in digests:
        digest = hashes.Hash(digests[lname])
        digest.update(key)
        digest.update(data)
        return digest.finalize()[:20]
    elif lname in algorithms:
        work = cmac.CMAC(algorithms[lname](poly.polybytes(key)))
        work.update(poly.polybytes(data))
        return work.finalize()[:20]
    return b''


class Authenticator:
    "MAC authentication manager for NTP packets."

    def __init__(self, keyfile=None):
        # We allow I/O and permission errors upward deliberately
        self.passwords = {}
        if keyfile is not None:
            for line in open(keyfile):
                if "#" in line:
                    line = line[: line.index("#")]
                line = line.strip()
                if not line:
                    continue
                (keyid, keytype, passwd) = line.split()
                if keytype.upper() in ["AES", "AES128CMAC"]:
                    keytype = "AES-128"
                if len(passwd) > 20:
                    # if len(passwd) > 64:
                    #      print('AUTH: Truncating key %s to 256bits (32Bytes)' % keyid)
                    passwd = util.hexstr2octets(passwd[:64])
                self.passwords[int(keyid)] = (keytype, passwd)

    def __len__(self):
        "return the number of keytype/passwd tuples stored"
        return len(self.passwords)

    def __getitem__(self, keyid):
        "get a keytype/passwd tuple by keyid"
        return self.passwords.get(keyid)

    def control(self, keyid=None):
        "Get the keytype/passwd tuple that controls localhost and its id"
        if keyid is not None:
            if keyid in self.passwords:
                return (keyid,) + self.passwords[keyid]
            else:
                return (keyid, None, None)
        for line in open("/etc/ntp.conf"):
            if line.startswith("control"):
                keyid = int(line.split()[1])
                (keytype, passwd) = self.passwords[keyid]
                if passwd is None:
                    # Invalid key ID
                    raise ValueError
                if len(passwd) > 20:
                    passwd = util.hexstr2octets(passwd)
                return (keyid, keytype, passwd)
        # No control lines found
        raise ValueError

    @staticmethod
    def compute_mac(payload, keyid, keytype, passwd):
        "Create the authentication payload to send"
        if not ntpc.checkname(keytype):
            return False
        mac2 = mac(
            poly.polybytes(payload),
            poly.polybytes(passwd),
            keytype,
        )[:20]
        if not mac2 or len(mac2) == 0:
            return b""
        return struct.pack("!I", keyid) + mac2

    @staticmethod
    def have_mac(packet):
        "Does this packet have a MAC?"
        # According to RFC 5909 7.5 the MAC is always present when an extension
        # field is present. Note: this crude test will fail on Mode 6 packets.
        # On those you have to go in and look at the count.
        return len(packet) > magic.LEN_PKT_NOMAC

    def verify_mac(self, packet, packet_end=48, mac_begin=48):
        "Does the MAC on this packet verify according to credentials we have?"
        payload = packet[:packet_end]
        keyid = packet[mac_begin : mac_begin + KEYID_LENGTH]
        mac = packet[mac_begin + KEYID_LENGTH :]
        (keyid,) = struct.unpack("!I", keyid)
        if keyid not in self.passwords:
            # print('AUTH: No key %08x...' % keyid)
            return False
        (keytype, passwd) = self.passwords[keyid]
        if not checkname(keytype):
            return False
        mac2 = mac(
            poly.polybytes(payload),
            poly.polybytes(passwd),
            keytype,
        )[:20]
        if not mac2:
            return False
        # typically preferred to avoid timing attacks client-side (in theory)
        try:
            return hmac.compare_digest(
                mac, mac2
            )  # supported 2.7.7+ and 3.3+
        except AttributeError:
            return mac == mac2  # solves issue #666


# end
