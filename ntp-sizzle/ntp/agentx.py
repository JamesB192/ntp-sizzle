# -*- coding: utf-8 -*-

# Copyright the NTPsec project contributors
#
# SPDX-License-Identifier: BSD-2-Clause

from __future__ import print_function, division

import select
import time
import sys

try:
    import ntp.util
    import ntp.agentx_packet

    ax = ntp.agentx_packet
except ImportError as e:
    sys.stderr.write(
        "AgentX: can't find Python AgentX Packet library.\n"
    )
    sys.stderr.write("%s\n" % e)
    sys.exit(1)


defaultTimeout = 30
pingTime = 60


def gen_next(generator):
    if str is bytes:  # Python 2
        return generator.next()
    return next(generator)  # Python 3


class MIBControl:
    def __init__(
        self,
        oid_tree=None,
        mib_root=(),
        range_subid=0,
        upper_bound=None,
        mib_context=None,
    ):
        self.oidTree = {}  # contains callbacks for the MIB
        if oid_tree is not None:
            self.oidTree = oid_tree
        # The undo system is only for the last operation
        self.inSetP = False  # Are we currently in the set procedure?
        self.setVarbinds = []  # Varbind of the current set operation
        self.setHandlers = []  # Handlers for commit/undo/cleanup of set
        self.setUndoData = []  # Previous values for undoing
        self.mibRoot = mib_root
        self.rangeSubid = range_subid
        self.upperBound = upper_bound
        self.context = mib_context

    def mib_rootOID(self):
        return self.mibRoot

    def mib_rangeSubid(self):
        return self.rangeSubid

    def mib_upperBound(self):
        return self.upperBound

    def mib_context(self):
        return self.context

    def addNode(self, oid, reader=None, writer=None, dynamic=None):
        if isinstance(oid, ax.OID):  # get it in a mungable format
            oid = tuple(oid.subids)
        # dynamic is the generator for tables
        current_level = self.oidTree
        remaining_oid = oid
        while True:
            node, remaining_oid = ntp.util.slicedata(remaining_oid, 1)
            node = node[0]
            if node not in current_level.keys():
                current_level[node] = {
                    "reader": None,
                    "writer": None,
                    "subids": None,
                }
            if not remaining_oid:  # We have reached the target node
                current_level[node]["reader"] = reader
                current_level[node]["writer"] = writer
                if dynamic is not None:
                    # can't be both dynamic and non-dynamic
                    current_level[node]["subids"] = dynamic
                return
            if current_level[node]["subids"] is None:
                current_level[node]["subids"] = {}
            current_level = current_level[node]["subids"]

    def getOID_core(self, next_p, searchoid, return_generator=False):
        gen = walkMIBTree(self.oidTree, self.mibRoot)
        while True:
            try:
                oid, reader, writer = gen_next(gen)
                if next_p:  # GetNext
                    # For getnext any OID greater than the start qualifies
                    oidhit = oid > searchoid
                else:  # Get
                    # For get we need a *specific* OID
                    oidhit = oid.subids == searchoid.subids
                if oidhit and (reader is not None):
                    # We only return OIDs that have a minimal implementation
                    # walkMIBTree handles the generation of dynamic trees
                    if return_generator:
                        return oid, reader, writer, gen
                    return oid, reader, writer
            except StopIteration:  # Couldn't find anything in the tree
                if return_generator:
                    return None, None, None, None
                return None, None, None

    # These exist instead of just using getOID_core so semantics are clearer
    def getOID(self, searchoid, return_generator=False):
        "Get the requested OID"
        return self.getOID_core(False, searchoid, return_generator)

    def getNextOID(self, searchoid, return_generator=False):
        "Get the next lexicographical OID"
        return self.getOID_core(True, searchoid, return_generator)

    def getOIDsInRange(self, oidrange, first_only=False):
        "Get a list of every (optionally the first) OID in a range"
        oids = []
        gen = walkMIBTree(self.oidTree, self.mibRoot)
        # Find the first OID
        while True:
            try:
                oid, reader, writer = gen_next(gen)
                if reader is None:
                    continue  # skip unimplemented OIDs
                if oid.subids == oidrange.start.subids:
                    # ok, found the start, do we need to skip it?
                    if oidrange.start.include:
                        oids.append((oid, reader, writer))
                        break
                    continue
                if oid > oidrange.start:
                    # If we are here it means we hit the start but skipped
                    if (
                        not oidrange.end.isNull()
                        and oid >= oidrange.end
                    ):
                        # We fell off the range
                        return []
                    oids.append((oid, reader, writer))
                    break
            except StopIteration:
                # Couldn't find *anything*
                return []
        if first_only:
            return oids
        # Start filling in the rest of the range
        while True:
            try:
                oid, reader, writer = gen_next(gen)
                if reader is None:
                    continue  # skip unimplemented OIDs
                if not oidrange.end.isNull() and oid >= oidrange.end:
                    break  # past the end of a bounded range
                oids.append((oid, reader, writer))
            except StopIteration:
                break  # We have run off the end of the MIB
        return oids


class PacketControl:
    def __init__(
        self,
        sock,
        dbase,
        spin_gap=0.001,
        timeout=defaultTimeout,
        logfp=None,
        debug=10000,
    ):
        self.log = lambda txt, dbg: ntp.util.dolog(
            logfp, txt, debug, dbg
        )
        # take a pre-made socket instead of making our own so that
        # PacketControl doesn't have to know or care about implementation
        self.socket = sock
        self.spinGap = spin_gap  # sleep() time on each loop
        # indexed on: (session_id, transaction_id, packet_id)
        # contains: (timeout, packet class)
        self.packetLog = (
            {}
        )  # Sent packets kept until response is received
        self.loopCallback = None  # called each loop in runforever mode
        self.database = dbase  # class for handling data requests
        self.receivedData = (
            b""  # buffer for data from incomplete packets
        )
        self.receivedPackets = []  # use as FIFO
        self.timeout = timeout
        self.sessionID = None  # need this for all packets
        self.highestTransactionID = 0  # used for exchanges we start
        self.lastReception = None
        self.stillConnected = False
        # indexed on pdu code
        self.pduHandlers = {
            ax.PDU_GET: self.handle_GetPDU,
            ax.PDU_GET_NEXT: self.handle_GetNextPDU,
            ax.PDU_GET_BULK: self.handle_GetBulkPDU,
            ax.PDU_TEST_SET: self.handle_TestSetPDU,
            ax.PDU_COMMIT_SET: self.handle_CommitSetPDU,
            ax.PDU_UNDO_SET: self.handle_UndoSetPDU,
            ax.PDU_CLEANUP_SET: self.handle_CleanupSetPDU,
            ax.PDU_RESPONSE: self.handle_ResponsePDU,
        }

    def mainloop(self, runforever):
        if self.stillConnected is not True:
            return False
        if runforever:
            while self.stillConnected:
                self._doloop()
                if self.loopCallback is not None:
                    self.loopCallback(self)
                time.sleep(self.spinGap)
        else:
            self._doloop()
        return self.stillConnected

    def _doloop(self):
        # loop body split out to separate the one-shot/run-forever switches
        # from the actual logic
        self.packetEater()
        while self.receivedPackets:
            packet = self.receivedPackets.pop(0)
            if packet.sessionID != self.sessionID:
                self.log(
                    "Received packet with incorrect session ID: %s"
                    % packet,
                    3,
                )
                resp = ax.ResponsePDU(
                    True,
                    packet.sessionID,
                    packet.transactionID,
                    packet.packetID,
                    0,
                    ax.RSPERR_NOT_OPEN,
                    0,
                )
                self.sendPacket(resp, False)
                continue
            ptype = packet.pduType
            if ptype in self.pduHandlers:
                self.pduHandlers[ptype](packet)
            else:
                self.log(
                    "Dropping packet type %i, not implemented" % ptype,
                    2,
                )
        self.checkResponses()
        if self.lastReception is not None:
            current_time = time.time()
            if (current_time - self.lastReception) > pingTime:
                self.sendPing()

    def initNewSession(self):
        self.log("Initializing new session...", 3)
        # We already have a connection, need to open a session.
        openpkt = ax.OpenPDU(
            True, 23, 0, 0, self.timeout, (), "NTPsec SNMP subagent"
        )
        self.sendPacket(openpkt, False)
        response = self.waitForResponse(openpkt, True)
        self.sessionID = response.sessionID
        # Register the tree
        register = ax.RegisterPDU(
            True,
            self.sessionID,
            1,
            1,
            self.timeout,
            1,
            self.database.mib_rootOID(),
            self.database.mib_rangeSubid(),
            self.database.mib_upperBound(),
            self.database.mib_context(),
        )
        self.sendPacket(register, False)
        self.waitForResponse(register)
        self.stillConnected = True

    def waitForResponse(self, opkt, ignore_sid=False):
        "Wait for a response to a specific packet, dropping everything else"
        while True:
            self.packetEater()
            while self.receivedPackets:
                packet = self.receivedPackets.pop(0)
                if packet.__class__ != ax.ResponsePDU:
                    continue
                haveit = (
                    opkt.transactionID == packet.transactionID
                ) and (opkt.packetID == packet.packetID)
                if not ignore_sid:
                    haveit = haveit and (
                        opkt.sessionID == packet.sessionID
                    )
                if haveit:
                    self.log("Received waited for response", 4)
                    return packet
            time.sleep(self.spinGap)

    def checkResponses(self):
        "Check for expected responses that have timed out"
        current_time = time.time()
        for key in list(self.packetLog.keys()):
            expiration, original_pkt, callback = self.packetLog[key]
            if current_time > expiration:
                if callback is not None:
                    callback(None, original_pkt)
                del self.packetLog[key]

    def packetEater(self):
        "Slurps data from the input buffer and tries to parse packets from it"
        self.pollSocket()
        while True:
            datalen = len(self.receivedData)
            if datalen < 20:
                return None  # We don't even have a packet header, bail
            try:
                pkt, full_pkt, extra_data = ax.decode_packet(
                    self.receivedData
                )
                if not full_pkt:
                    return None
                self.receivedData = extra_data
                self.receivedPackets.append(pkt)
                if pkt.transactionID > self.highestTransactionID:
                    self.highestTransactionID = pkt.transactionID
                self.log("Received a full packet: %s" % repr(pkt), 4)
            except (
                ax.ParseVersionError,
                ax.ParsePDUTypeError,
                ax.ParseError,
            ) as error:
                if error.header["type"] != ax.PDU_RESPONSE:
                    # Response errors are silently dropped, per RFC
                    # Everything else sends an error response
                    self.sendErrorResponse(
                        error.header, ax.RSPERR_PARSE_ERROR, 0
                    )
                # *Hopefully* the packet length was correct.....
                #  if not, all packets will be scrambled. Maybe dump the
                #  whole buffer if too many failures in a row?
                self.receivedData = error.remainingData

    def sendPacket(
        self,
        packet,
        expects_reply,
        reply_timeout=defaultTimeout,
        callback=None,
    ):
        encoded = packet.encode()
        self.log(
            "Sending packet (with reply: %s): %s"
            % (expects_reply, repr(packet)),
            4,
        )
        self.socket.sendall(encoded)
        if expects_reply:
            index = (
                packet.sessionID,
                packet.transactionID,
                packet.packetID,
            )
            self.packetLog[index] = (reply_timeout, packet, callback)

    def sendPing(self):
        # DUMMY packetID, does this need to change? or does the pktID only
        # count relative to a given transaction ID?
        tid = self.highestTransactionID + 5  # +5 to avoid collisions
        self.highestTransactionID = tid
        pkt = ax.PingPDU(True, self.sessionID, tid, 1)

        def callback(resp, _):  # orig
            if resp is None:  # Timed out. Need to restart the session.
                # Er, problem: Can't handle reconnect from inside PacketControl
                self.stillConnected = False

        self.sendPacket(pkt, True, callback=callback)

    def sendNotify(self, varbinds, context=None):
        # DUMMY packetID, does this need to change? or does the pktID only
        # count relative to a given transaction ID?
        tid = self.highestTransactionID + 5  # +5 to avoid collisions
        self.highestTransactionID = tid
        pkt = ax.NotifyPDU(
            True, self.sessionID, tid, 1, varbinds, context
        )

        def resendNotify(pkt, orig):
            if pkt is None:
                self.sendPacket(orig, True, callback=resendNotify)

        self.sendPacket(pkt, True, resendNotify)

    def sendErrorResponse(self, error_header, error_type, error_index):
        err = ax.ResponsePDU(
            error_header["flags"]["bigEndian"],
            error_header["session_id"],
            error_header["transaction_id"],
            error_header["packet_id"],
            0,
            error_type,
            error_index,
        )
        self.sendPacket(err, False)

    def pollSocket(self):
        "Reads all currently available data from the socket, non-blocking"
        data = b""
        while True:
            tmp = select.select([self.socket], [], [], 0)[0]
            if not tmp:  # No socket, means no data available
                break
            tmp = tmp[0]
            newdata = tmp.recv(4096)  # Arbitrary value
            if newdata:
                self.log("Received data: %s" % repr(newdata), 5)
                data += newdata
                self.lastReception = time.time()
            else:
                break
        self.receivedData += data

    # ==========================
    # Packet handlers start here
    # ==========================

    def handle_GetPDU(self, packet):
        binds = []
        for oidr in packet.oidranges:
            target = oidr.start
            oid, reader, _ = self.database.getOID(target)
            if (oid != target) or (reader is None):
                # This OID must not be implemented yet.
                binds.append(
                    ax.Varbind(ax.VALUE_NO_SUCH_OBJECT, target)
                )
            else:
                vbind = reader(oid)
                if vbind is None:  # No data available.
                    # I am not certain that this is the correct response
                    # when no data is available. snmpwalk appears to stop
                    # calling a particular sub-agent when it gets to a NULL.
                    binds.append(ax.Varbind(ax.VALUE_NULL, target))
                else:
                    binds.append(vbind)
            # There should also be a situation that leads to noSuchInstance
            #  but I do not understand the requirements for that
        # TODO: Need to implement genError
        resp = ax.ResponsePDU(
            True,
            self.sessionID,
            packet.transactionID,
            packet.packetID,
            0,
            ax.ERR_NOERROR,
            0,
            binds,
        )
        self.sendPacket(resp, False)

    def handle_GetNextPDU(self, packet):
        binds = []
        for oidr in packet.oidranges:
            while True:
                oids = self.database.getOIDsInRange(oidr, True)
                if not oids:  # Nothing found
                    binds.append(
                        ax.Varbind(ax.VALUE_END_OF_MIB_VIEW, oidr.start)
                    )
                    break
                oid, reader, _ = oids[0]
                vbind = reader(oid)
                if vbind is None:  # No data available
                    # Re-do search for this OID range, starting from just
                    # after the current location
                    oidr = ax.SearchRange(oid, oidr.end, False)
                    continue
                binds.append(vbind)
                break
        # TODO: Need to implement genError
        resp = ax.ResponsePDU(
            True,
            self.sessionID,
            packet.transactionID,
            packet.packetID,
            0,
            ax.ERR_NOERROR,
            0,
            binds,
        )
        self.sendPacket(resp, False)

    def handle_GetBulkPDU(self, packet):
        binds = []
        nonreps = packet.oidranges[: packet.nonReps]
        repeats = packet.oidranges[packet.nonReps :]
        # Handle non-repeats
        for oidr in nonreps:
            oids = self.database.getOIDsInRange(oidr, True)
            if not oids:  # Nothing found
                binds.append(
                    ax.Varbind(ax.VALUE_END_OF_MIB_VIEW, oidr.start)
                )
            else:
                oid, reader, _ = oids[0]
                binds.append(reader(oid))
        # Handle repeaters
        for oidr in repeats:
            oids = self.database.getOIDsInRange(oidr)
            if not oids:  # Nothing found
                binds.append(
                    ax.Varbind(ax.VALUE_END_OF_MIB_VIEW, oidr.start)
                )
            else:
                for oid, reader, _ in oids[: packet.maxReps]:
                    binds.append(reader(oid))
        resp = ax.ResponsePDU(
            True,
            self.sessionID,
            packet.transactionID,
            packet.packetID,
            0,
            ax.ERR_NOERROR,
            0,
            binds,
        )
        self.sendPacket(resp, False)

    def handle_TestSetPDU(self, packet):  # WIP / TODO
        # Be advised: MOST OF THE VALIDATION IS DUMMY CODE OR DOESN'T EXIST
        # According to the RFC this is one of the most demanding parts and
        #  *has* to be gotten right
        if self.database.inSetP:
            pass  # Is this an error?
        # if (inSetP) is an error these will go in an else block
        self.database.inSetP = True
        self.database.setVarbinds = []
        self.database.setHandlers = []
        self.database.setUndoData = []
        error = None
        for bind_index in range(len(packet.varbinds)):
            varbind = packet.varbinds[bind_index]
            # Find an OID, then validate it
            oid, reader, writer = self.database.getOID(varbind.oid)
            if oid is None:  # doesn't exist, can we create it?
                # DUMMY, assume we can't create anything
                error = ax.ERR_NO_ACCESS
                break
            if writer is None:  # exists, writing not implemented
                error = ax.ERR_NOT_WRITABLE
                break
            # Ok, we have an existing or new OID, assemble the orders
            # If we created a new bind undoData is None, must delete it
            undo_data = reader(oid)
            error = writer("test", varbind)
            if error != ax.ERR_NOERROR:
                break
            self.database.setVarbinds.append(varbind)
            self.database.setHandlers.append(writer)
            self.database.setUndoData.append(undo_data)
        if error != ax.ERR_NOERROR:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                error,
                bind_index,
            )
            self.sendPacket(resp, False)
            for i in range(bind_index):
                # Errored out, clear the successful ones
                self.database.setHandlers[i](
                    "clear", self.database.setVarbinds[i]
                )
            self.database.inSetP = False
        else:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                ax.ERR_NOERROR,
                0,
            )
            self.sendPacket(resp, False)

    def handle_CommitSetPDU(self, packet):
        if not self.database.inSetP:
            pass  # how to handle this?
        varbinds = self.database.setVarbinds
        handlers = self.database.setHandlers
        for i in range(len(varbinds)):
            error = handlers[i]("commit", varbinds[i])
            if error != ax.ERR_NOERROR:
                break
        if error != ax.ERR_NOERROR:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                error,
                i,
            )
        else:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                ax.ERR_NOERROR,
                0,
            )
        self.sendPacket(resp, False)

    def handle_UndoSetPDU(self, packet):
        varbinds = self.database.setVarbinds
        handlers = self.database.setHandlers
        undo_data = self.database.setUndoData
        for i in range(len(varbinds)):
            error = handlers[i]("undo", varbinds[i], undo_data[i])
            if error != ax.ERR_NOERROR:
                break
        if error != ax.ERR_NOERROR:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                error,
                i,
            )
        else:
            resp = ax.ResponsePDU(
                True,
                self.sessionID,
                packet.transactionID,
                packet.packetID,
                0,
                ax.ERR_NOERROR,
                0,
            )
        self.sendPacket(resp, False)

    def handle_CleanupSetPDU(self, _):  # packet
        varbinds = self.database.setVarbinds
        handlers = self.database.setHandlers
        for i in range(len(varbinds)):
            handlers[i]("clean", varbinds[i])
        self.database.inSetP = False

    def handle_ResponsePDU(self, packet):
        index = (
            packet.sessionID,
            packet.transactionID,
            packet.packetID,
        )
        if index in self.packetLog:
            _, original_packet, callback = self.packetLog[
                index
            ]  # timeout
            del self.packetLog[index]
            if callback is not None:
                callback(packet, original_packet)
        else:
            # Ok, response with no associated packet.
            # Probably something that timed out.
            pass


def walkMIBTree(tree, rootpath=()):
    # Tree node formats:
    # {"reader": <func>, "writer": <func>, "subids": {.blah.}}
    # {"reader": <func>, "writer": <func>, "subids": <func>}
    # The "subids" function in dynamic nodes must return an MIB tree
    node_stack = []
    oid_stack = []
    current = tree
    current_keys = list(current.keys())
    current_keys.sort()
    key_id = 0
    while True:
        if key_id >= len(current_keys):
            if node_stack:
                # No more nodes this level, pop higher node
                current, current_keys, key_id, key = node_stack.pop()
                oid_stack.pop()
                key_id += 1
                continue
            return
        key = current_keys[key_id]
        oid = ax.OID(rootpath + tuple(oid_stack) + (key,))
        yield (
            oid,
            current[key].get("reader"),
            current[key].get("writer"),
        )
        subs = current[key].get("subids")
        if subs is not None:
            # Push current node, move down a level
            node_stack.append((current, current_keys, key_id, key))
            oid_stack.append(key)
            if isinstance(subs, dict):
                current = subs
            else:
                current = subs()  # Tree generator function
                if current == {}:  # no dynamic subids, pop
                    (
                        current,
                        current_keys,
                        key_id,
                        key,
                    ) = node_stack.pop()
                    oid_stack.pop()
                    key_id += 1
                    continue
            current_keys = list(current.keys())
            current_keys.sort()
            key_id = 0
            key = current_keys[key_id]
            continue
        key_id += 1
