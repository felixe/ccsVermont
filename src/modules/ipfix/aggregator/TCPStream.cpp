/*
 * Vermont Aggregator Subsystem
 * Copyright (C) 2014 Vermont Project
 * Author: Wolfgang Estgfaeller <wolfgang@estgfaeller.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include "TCPStream.h"
#include "modules/ipfix/FlowAnnotation.h"
#include <sstream>

TCPStream::TCPStream(Packet* p, uint32_t num) :
        streamNum(num), direction(FORWARD), state(TCPStream::TCP_UNDEFINED), httpData(0), bufferedSize(0), truncatedPackets(false), sequenceGaps(false), outOfBufferSpace(false) {
    // values are stored in network byte order since the values are only used for calculating the hash
    hkey.srcIp = *reinterpret_cast<uint32_t*>(p->data.netHeader + OFFSET_SRC_IP);       // source IP
    hkey.dstIp = *reinterpret_cast<uint32_t*>(p->data.netHeader + OFFSET_DST_IP);       // destination IP
    hkey.srcPort = *reinterpret_cast<uint16_t*>(p->transportHeader + OFFSET_SRC_PORT);  // source port
    hkey.dstPort = *reinterpret_cast<uint16_t*>(p->transportHeader + OFFSET_DST_PORT);  // destination port
    tcpForcedExpiry.reset(new bool);
    (*tcpForcedExpiry.get()) = false;
    tcpFlowAnnotations.reset(new uint32_t);
    (*tcpFlowAnnotations.get()) = 0;
}


TCPStream::~TCPStream() {
    (*tcpForcedExpiry.get()) = true;
    if (!httpData)
        return;
    if (httpData->forwardLine)
        free(httpData->forwardLine);
    if (httpData->reverseLine)
        free(httpData->reverseLine);
    delete httpData;
    releaseQueuedPackets();
    if (fwdData.packetQueue.size() > 0 || revData.packetQueue.size() > 0)
        THROWEXCEPTION("TCPstream was not deleted properly. there are still packet instances in use.");
}

/**
 * Updates the direction of the stream to the current direction, i.e. FORWARD or REVERSE.
 * The direction is determined with the TCPStream::hkey member. See ::hkey_t for more information.
 * @param p packet which specifies the new direction
 */
void TCPStream::updateDirection(Packet* p) {
    if (hkey.srcIp == (*reinterpret_cast<uint32_t*>(p->data.netHeader + OFFSET_SRC_IP)) &&
            (hkey.srcPort == *reinterpret_cast<uint16_t*>(p->transportHeader + OFFSET_SRC_PORT))) {
        direction = FORWARD;
    } else {
        direction = REVERSE;
    }
}

/**
 * Releases all queued packets.
 */
void TCPStream::releaseQueuedPackets() {
    releaseQueuedPackets(fwdData.packetQueue);
    releaseQueuedPackets(revData.packetQueue);
    bufferedSize = 0;
}

/**
 * Releases all queued packets from the given PacketQueue.
 * @param packetQueue
 */
void TCPStream::releaseQueuedPackets(PacketQueue& packetQueue) {
    PacketQueue::const_iterator pit = packetQueue.begin();
    for (;pit!=packetQueue.end();pit++) {
        // remove reference to Packet instance
        (*pit).second->removeReference();
#ifdef DEBUG
    int32_t refCount = (*pit).second->getReferenceCount();
    if (refCount != 0)
        THROWEXCEPTION("wrong reference count: %d. expected: 0", refCount);
#endif
    }
    TCPMonitor::statTotalSkippedBufferedPackets+=packetQueue.size();
    packetQueue.clear();
}

/**
 * Releases all obsolete queued packets from the given PacketQueue.
 * @param packetQueue
 */
void TCPStream::releaseObsoleteQueuedPackets(TCPData& tcpData) {
    PacketQueue& packetQueue = tcpData.packetQueue;
    PacketQueue::iterator pit = packetQueue.begin();
    for (;pit!=packetQueue.end();) {
        Packet* p = (*pit).second;
        uint32_t seq = ntohl(*reinterpret_cast<uint32_t*>(p->transportHeader + OFFSET_SEQ));
        if (seq != tcpData.nextSeq && !TCPMonitor::isFresh(seq, tcpData)) {
            uint32_t slen = p->net_total_length - p->payloadOffset; // TCP segment length
            bufferedSize -= slen;
            // remove reference to Packet instance
            p->removeReference();
#ifdef DEBUG
            int32_t refCount = p->getReferenceCount();
            if (refCount != 0)
                THROWEXCEPTION("wrong reference count: %d. expected: 0", refCount);
#endif
            TCPMonitor::statTotalSkippedPacketsInGaps++;
            packetQueue.erase(pit++);
        } else {
            if (seq==tcpData.nextSeq)
                tcpData.packetsAvailable = true;
            ++pit;
        }
    }
}

/**
 * Convenience function to set flow annotation flag
 * @param annotation Annotation flag to be set
 */
void TCPStream::addAnnotationFlag(uint32_t annotation) {
    *tcpFlowAnnotations.get() = *tcpFlowAnnotations.get() | annotation;
}

/**
 * Prints the TCPStream::hkey in a human readable format (network 4-tuple)
 */
void TCPStream::printKey() {
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &hkey.srcIp, srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &hkey.dstIp, dstIp, INET_ADDRSTRLEN);
    msg(MSG_DEBUG, "tcpmon: src ip=%s port=%d, dst ip=%s port=%d", srcIp, ntohs(hkey.srcPort), dstIp, ntohs(hkey.dstPort));
}

/**
 * Prints the number of queued packets for a stream
 */
void TCPStream::printQueueStats() {
    msg(MSG_VDEBUG, "tcpmon: queued packets: %lu", fwdData.packetQueue.size() + revData.packetQueue.size());
}

bool TCPStream::isForward() {
    return direction == FORWARD;
}

bool TCPStream::isReverse() {
    return direction == REVERSE;
}

// equality function for the StreamHashTable
bool operator==(const TCPStream& a, const TCPStream& b) {
    return (a.hkey.srcIp == b.hkey.srcIp
            && a.hkey.dstIp == b.hkey.dstIp
            && a.hkey.srcPort == b.hkey.srcPort
            && a.hkey.dstPort == b.hkey.dstPort) ||
            (a.hkey.srcIp == b.hkey.dstIp
            && a.hkey.dstIp == b.hkey.srcIp
            && a.hkey.srcPort == b.hkey.dstPort
            && a.hkey.dstPort == b.hkey.srcPort);
}

// hash function for the StreamHashTable
std::size_t hash_value(const TCPStream& b) {
    size_t seed = 0;
    // by combining the values the following way we get the same hash value in both directions, which is required
    boost::hash_combine(seed, b.hkey.srcIp ^ b.hkey.dstIp); // src ip XOR dst ip
    boost::hash_combine(seed, b.hkey.srcPort ^ b.hkey.dstPort); // src port XOR dst port
    return seed;
}

TCPMonitor::TCPMonitor(uint32_t htableSize, uint32_t timeoutAttempted, uint32_t timeoutEstablished, uint32_t timeoutClosed, uint32_t maxBufferedBytes, uint32_t maxBufferedBytesHTTP, bool usePCAPTimestamps_) :
        streamCounter(0) {
    // initialize 'htableSize' buckets for the hashtable
    base_buckets = new StreamHashTable::bucket_type[htableSize];
    // initialize the hashtable
    htable = new StreamHashTable(StreamHashTable::bucket_traits(base_buckets, htableSize));

    TIMEOUT_ATTEMPTED = timeoutAttempted ? timeoutAttempted : DEF_TIMEOUT_ATTEMPTED;
    TIMEOUT_ESTABLISHED = timeoutEstablished ? timeoutEstablished : DEF_TIMEOUT_ESTABLISHED;
    TIMEOUT_CLOSED = timeoutClosed ? timeoutClosed : DEF_TIMEOUT_CLOSED;
    MAX_BUFFERED_BYTES = maxBufferedBytes ? maxBufferedBytes : DEF_TCP_BUFFER_SIZE;
    MAX_BUFFERED_BYTES_HTTP = maxBufferedBytesHTTP ? maxBufferedBytesHTTP : HTTPAggregation::DEF_MAX_BUFFERED_BYTES;

    usePCAPTimestamps = usePCAPTimestamps_;

    SensorManager::getInstance().addSensor(this, "TCPMonitor", 0);

    msg(MSG_INFO, "TCPMonitor initialized with the following parameters:");
    msg(MSG_INFO, "  - attemptedConnectionTimeout = %u ms", TIMEOUT_ATTEMPTED);
    msg(MSG_INFO, "  - establishedConnectionTimeout = %u ms", TIMEOUT_ESTABLISHED);
    msg(MSG_INFO, "  - closedConnectionTimeout = %u ms", TIMEOUT_CLOSED);
    msg(MSG_INFO, "  - use PCAP timestamps = %s", usePCAPTimestamps ? "yes" : "no" );
    msg(MSG_INFO, "  - TCP connection buffer size = %u bytes", MAX_BUFFERED_BYTES);
    msg(MSG_INFO, "  - HTTP message buffer size = %u bytes", MAX_BUFFERED_BYTES_HTTP);
}

TCPMonitor::~TCPMonitor() {
    expireStreams(true);
    delete htable;
    delete[] base_buckets;
}

/**
 * Find a matching TCPStream for the passed Packet. If no matching TCPStream exists
 * a new one is created. The timeout value for the TCPStream is updated accordingly.
 * Afterwards the Packet gets analyzed and the TCPStream gets updated with new TCP
 * connection related information. If a Packet is out of order it gets registered to
 * the TCPStream and NULL is returned.
 * @param p The packet which should be analyzed and registered to the TCPMonitor
 * @return a matching TCPStream or NULL if the Packet is out of order
 */
int TCPMonitor::dissect(Packet* p, TCPStream** ts) {
    statTotalPackets++;
    statTotalSegmentBytes += (p->net_total_length - p->payloadOffset);

    *ts = findOrCreateStream(p);

    if (usePCAPTimestamps)
        currentTimestamp = p->timestamp;

    if (p->pcapPacketLength > p->data_length_uncropped) {
        statTotalTruncatedPackets++;
        if (!(*ts)->truncatedPackets) {
            (*ts)->truncatedPackets = true;
            DPRINTFL(MSG_DEBUG, "tcpmon: WARNING, this TCP connection contains truncated packets");
        }
    }

    // update the timeout timestamp of the TCPStream
    refreshTimeout((*ts));

// To reconsider: Packets which arrive after a stream was marked as closed could be
// skipped... But for now we don't skip them
//
//    // if the TCP stream was closed before we do not have to consider this Packet
//    if ((*ts)->state == TCPStream::TCP_CLOSED) {
//        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet, TCP connection was closed before");
//        statTotalSkippedPacketsAfterClose++;
//#ifdef DEBUG
//    int32_t refCount = p->getReferenceCount();
//    if (refCount != 1)
//        THROWEXCEPTION("wrong reference count: %d. expected: 1", refCount);
//#endif
//        return TCPMonitor::CLOSED;
//    }

    (*ts)->updateDirection(p);

    // perform TCP connection analysis
    if (!analysePacket(p, (*ts))) {
        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet, packet is out of order.");
        return TCPMonitor::OUT_OF_ORDER;
    }

    statTotalPacketsProcessed++;
    statTotalSegmentBytesProcessed += (p->net_total_length - p->payloadOffset);
    return TCPMonitor::IN_ORDER;
}

/**
 * Analyze a Packet and manage the TCP connection accordingly.
 * This is the place where most of the TCPMonitor magic happens. We perform
 * several checks regarding the sequence number and acknowledgement number, which
 * allows us to determine when a TCP connection starts and ends, Packets are
 * observed in order and more.
 * @param p the Packet which should be analyzed
 * @param ts the TCPStream to which the Packet belongs
 * @return True if the Packet is in order, false otherwise
 */
bool TCPMonitor::analysePacket(Packet* p, TCPStream* ts) {
    // get required fields from the TCP header
    uint32_t ack = ntohl(*reinterpret_cast<uint32_t*>(p->transportHeader + OFFSET_ACK));
    uint32_t seq = ntohl(*reinterpret_cast<uint32_t*>(p->transportHeader + OFFSET_SEQ));
    uint8_t flags = *reinterpret_cast<uint8_t*>(p->transportHeader + OFFSET_FLAGS) & 0x3F;

    // TCPData from the originator of the Packet
    TCPData& src = ts->isForward() ? ts->fwdData : ts->revData;
    // TCPData from the destination of the Packet
    TCPData& dst = ts->isReverse() ? ts->fwdData : ts->revData;

    uint32_t slen = p->net_total_length - p->payloadOffset; // TCP segment length

    DPRINTFL(MSG_VDEBUG, "tcpmon: seq#: %u, is next:%s, ack#: %u, flags: SYN=%d, ACK=%d, FIN=%d, RST=%d, plen: %u, slen:%u",
            seq, seq == src.nextSeq ? "yes":"no", ack, (bool)(flags&FLAG_SYN), (bool)(flags&FLAG_ACK), (bool)(flags&FLAG_FIN), (bool)(flags&FLAG_RST), p->pcapPacketLength, slen);

    if (isSet(flags, FLAG_SYN | FLAG_FIN) || isSet(flags, FLAG_SYN | FLAG_RST)) {
        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet with an illegal combination of TCP flags: : SYN=%d, ACK=%d, FIN=%d, RST=%d",
                (bool)(flags&FLAG_SYN), (bool)(flags&FLAG_ACK), (bool)(flags&FLAG_FIN), (bool)(flags&FLAG_RST));
        statTotalInvalidPackets++;
        return false;
    } else if (isSet(flags, FLAG_SYN) && !isSet(flags, FLAG_ACK) && src.initSeq==0 && src.initSeq != seq) {
        // this is a connection attempt, i.e. a SYN packet
        DPRINTFL(MSG_INFO, "tcpmon: TCP handshake: connection attempt (SYN)");
        src.initSeq = seq;
        src.nextSeq = seq + 1;
        if (ts->state == TCPStream::TCP_UNDEFINED)
            statTotalHalfEstablishedConnections++;
        changeState(ts, TCPStream::TCP_ATTEMPT);
    } else if (isSet(flags, FLAG_SYN | FLAG_ACK) && src.initSeq==0 && src.initSeq != seq && dst.initSeq + 1 == ack) {
        // connection established, i.e. a SYN+ACK packet has been seen after a SYN
        DPRINTFL(MSG_INFO, "tcpmon: TCP handshake: connection established (SYN+ACK)");
        src.initSeq = seq;
        src.nextSeq = seq + 1;

        // update the state of the TCPStream and move it to the proper timeout list
        changeState(ts, TCPStream::TCP_ESTABLISHED, true);
    } else if (isSet(flags, FLAG_FIN) && src.seqFin == 0 && (src.nextSeq == seq || (src.initSeq == 0 && src.nextSeq == 0))) {

        // if this is the first observed packet
        if (ts->state == TCPStream::TCP_UNDEFINED || ts->state == TCPStream::TCP_ATTEMPT) {
            ts->addAnnotationFlag(FlowAnnotation::TCP_NO_HANDSHAKE);
            // update the state of the TCPStream and move it to the proper timeout list
            changeState(ts, TCPStream::TCP_ESTABLISHED);
        }
        if (src.initSeq == 0 && src.nextSeq == 0) {
            // guess the initial sequence number equals actual seq - 1
            src.initSeq = seq - 1;
            if (dst.initSeq == 0 && dst.nextSeq == 0 && isSet(flags, FLAG_ACK)) {
                // guess the initial sequence number in the other direction equals to ack - 1
                dst.initSeq = ack - 1;
                // guess the next sequence number in the other direction equals to ack
                dst.nextSeq = ack;
            }
        }

        if (dst.seqFin==0) {
            // one party requests to close the connection
            DPRINTFL(MSG_INFO, "tcpmon: TCP termination: closing connection");
        }
        else {
            // the other party also wants to close the connection,
            // so the TCP termination can be considered as complete
            DPRINTFL(MSG_INFO, "tcpmon: TCP termination: connection closed");
            if (ts->state != TCPStream::TCP_CLOSED) {
                statTotalTerminatedConnections++;
            }
            // update the state of the TCPStream and move it to the proper timeout list
            changeState(ts, TCPStream::TCP_CLOSED);
        }

        src.nextSeq = seq + 1 + slen;
        src.seqFin = seq + slen;
    } else if (isSet(flags, FLAG_RST) && ts->state != TCPStream::TCP_CLOSED) {
        if(ts->state == TCPStream::TCP_ATTEMPT && isSet(flags, FLAG_ACK) && seq == 0 && ack != dst.initSeq+1) {
            // invalid RST packet
            DPRINTFL(MSG_ERROR, "tpcmon: invalid RST packet, ACKed wrong sequence number");
            return false;
        }

        if (seq != src.nextSeq && !(src.initSeq == 0 && src.nextSeq == 0)) {
            // invalid RST packet
            DPRINTFL(MSG_ERROR, "tpcmon: invalid RST packet, wrong sequence number");
            return false;
        }

        // discovered a RST packet, immediately close the connection
        DPRINTFL(MSG_INFO, "tcpmon: TCP RST discovered: connection closed");

        // if this is the first observed packet
        if (ts->state == TCPStream::TCP_UNDEFINED) {
            statTotalEstablishedConnections++;
            statTotalNonRegularEstablishedConnections++;
            ts->addAnnotationFlag(FlowAnnotation::TCP_NO_HANDSHAKE);
        }

        if (src.initSeq == 0 && src.nextSeq == 0) {
            // guess the initial sequence number equals actual seq - 1
            src.initSeq = seq - 1;
            if (dst.initSeq == 0 && dst.nextSeq == 0 && isSet(flags, FLAG_ACK)) {
                // guess the initial sequence number in the other direction equals to ack - 1
                dst.initSeq = ack - 1;
                // guess the next sequence number in the other direction equals to ack
                dst.nextSeq = ack;
            }
        }

        if (ts->state != TCPStream::TCP_CLOSED) {
            statTotalResettedConnections++;
        }
        // update the state of the TCPStream and move it to the proper timeout list
        changeState(ts, TCPStream::TCP_CLOSED);

        src.nextSeq = seq + 1 + slen;
        src.seqFin = seq + slen;
    } else if (src.nextSeq == seq) {
        // this data packet is in order, update next sequence number
        DPRINTFL(MSG_DEBUG, "tcpmon: ordinary data packet, setting next seq nr to %u", seq + slen);
        src.nextSeq = seq + slen;
        if (isSet(flags, FLAG_ACK))
            processACK(ts, ack, dst);
    } else {
        if (src.initSeq == 0 && src.nextSeq == 0 && (ts->state == TCPStream::TCP_UNDEFINED || ts->state == TCPStream::TCP_ATTEMPT)) {
            // for some reason we did not discover the initial sequence number.
            // guess the initial sequence number equals actual seq - 1
            src.initSeq = seq - 1;
            src.nextSeq = seq + slen;

            statTotalNonRegularEstablishedConnections++;
            ts->addAnnotationFlag(FlowAnnotation::TCP_NO_HANDSHAKE);

            // update the state of the TCPStream and move it to the proper timeout list
            changeState(ts, TCPStream::TCP_ESTABLISHED);
            DPRINTFL(MSG_INFO, "tcpmon: TCP new connection established (handshake was not observed)");

            if (isSet(flags, FLAG_ACK))
                processACK(ts, ack, dst);
        } else if (src.nextSeq) {
            if (isSet(flags, FLAG_ACK))
                processACK(ts, ack, dst);

            if (isFresh(seq, src)) {
                // this is a new unseen packet which is out-of-order
                statTotalOutOfOrderPackets++;
                PacketQueue& packetQueue = ts->isForward() ? ts->fwdData.packetQueue : ts->revData.packetQueue;
                PacketQueue::iterator it = packetQueue.find(PacketQueue::key_type(seq));
                if (it == packetQueue.end()) {
                    if (ts->bufferedSize + p->pcapPacketLength > MAX_BUFFERED_BYTES) {
                        statTotalBufferOverflows++;
                        ts->addAnnotationFlag(FlowAnnotation::TCP_OUT_OF_BUFFER);
                        DPRINTFL(MSG_DEBUG, "tcpmon: out of buffer space! cannot proceed with TCP reassembly for stream with hash %lu.", hash_value(*ts));
                        // clear all cached packets
                        ts->releaseQueuedPackets();
                        // mark stream as removable
                        ts->outOfBufferSpace = true;
                        // refresh the timeout. since we marked the stream as removable
                        // it will be put in front of the proper queue and deleted as soon as possible.
                        refreshTimeout(ts, true);
                        return false;
                    }
                    statBufferedPackets++;
                    statTotalBufferedPackets++;
                    packetQueue.insert(PacketQueue::value_type(seq, p));
                    p->addReference();
                    DPRINTFL(MSG_DEBUG, "tcpmon: non contiguous sequence number. inserting packet with seq# %u into PacketQueue for later processing.", seq);
                    ts->bufferedSize += p->pcapPacketLength;
                }
            } else {
                // this sequence number has been seen previously and should not have to be processed
                if (!(flags & (FLAG_SYN | FLAG_FIN | FLAG_RST)) && ((seq == src.nextSeq && slen == 0) || ((seq == src.nextSeq - 1 && slen == 1))))
                    DPRINTFL(MSG_DEBUG, "tcpmon: packet is out of order. this should be a TCP keep-alive packet.");
                else
                    DPRINTFL(MSG_DEBUG, "tcpmon: packet is out of order. not considering packet because the sequence number should already have been processed.");
            }
            return false;
        }
#ifdef DEBUG
        else {
            THROWEXCEPTION("this state should be unreachable");
        }
#endif
    }
    return true;
}

/**
 * Analyze the ACK field. Checks for sequence gaps resulting from a packet loss and trims them if needed
 * @param ts Reference to TCPStream
 * @param ack Received ACK
 * @param dst TCPData of the packet's destination
 */
void TCPMonitor::processACK(TCPStream* ts, uint32_t ack, TCPData& dst) {
    if (ack > 0) {
        int seqDiff = isFresh(ack, dst);
        if (!ts->sequenceGaps && seqDiff) {
            DPRINTFL(MSG_DEBUG, "ACKed unseen segment. this TCP connection may contain sequence gaps!");
            ts->sequenceGaps = true;
        }
        if (dst.initSeq == 0 && dst.nextSeq == 0) {
            // guess the initial sequence number in the other direction equals to ack - 1
            dst.initSeq = ack - 1;
            // guess the next sequence number in the other direction equals to ack
            dst.nextSeq = ack;
        } else if (seqDiff){
            // a sequence gap was observed
            DPRINTFL(MSG_VDEBUG, "skipping gap from seq %u to %u (%u bytes)", dst.nextSeq, ack, seqDiff);
            uint32_t& lostBytesInDirection = ts->isForward() ? ts->httpData->forwardLostBytes : ts->httpData->reverseLostBytes;

            lostBytesInDirection += seqDiff;
            statTotalSkippedBytes += seqDiff;

            dst.nextSeq = ack;
            ts->releaseObsoleteQueuedPackets(dst);
            ts->addAnnotationFlag(FlowAnnotation::TCP_SEQ_GAPS);
            statTotalSkippedGaps++;
        }
    }
}

/**
 * Check if the TCPStream contains queued Packets which can be processed.
 * If a Packet is in order, i.e. the sequence number matches the next expected
 * in the current direction TCPData::nextSeq, the Packet is returned.
 * @param ts TCPStream which should be checked
 * @return The next queued Packet in order, or NULL if no Packet was queued which is in order.
 */
Packet* TCPMonitor::nextPacketForStream(TCPStream* ts) {
    // lookup for a queued Packet which is in order
    TCPData& src = ts->isForward() ? ts->fwdData : ts->revData;
    uint32_t nseq = src.nextSeq;
    PacketQueue* packetQueue = ts->isForward() ? &ts->fwdData.packetQueue : &ts->revData.packetQueue;
    PacketQueue::iterator it = packetQueue->find(nseq);
    if (it == packetQueue->end()) {
        TCPData& dst = ts->isForward() ? ts->revData : ts->fwdData;
        if (dst.packetsAvailable) {
            nseq = dst.nextSeq;
            packetQueue = ts->isForward() ? &ts->revData.packetQueue : &ts->fwdData.packetQueue;
            it = packetQueue->find(nseq);
            dst.packetsAvailable = false;
        }
        if (it == packetQueue->end())
            return NULL;
        ts->updateDirection((*it).second);
        DPRINTFL(MSG_DEBUG, "tcpmon: switching direction! proceeding with packet in opposite direction.");
    }

    Packet* p = (*it).second;
    DPRINTFL(MSG_DEBUG, "tcpmon: processing queued packet with sequence number: %u", nseq);

    // delete the Packet from the queue
    packetQueue->erase(it);
    ts->bufferedSize -= p->pcapPacketLength;

#ifdef DEBUG
    uint32_t seq = ntohl(*reinterpret_cast<uint32_t*>(p->transportHeader + OFFSET_SEQ));
    if (seq != nseq)
        THROWEXCEPTION("sequence number of stored packet does not match.");
#endif

    // perform TCP analysis
    bool result = analysePacket(p, ts);

    if (!result) {
        return NULL;
    }

#ifdef DEBUG
    if (packetQueue->find(nseq)!=packetQueue->end())
        THROWEXCEPTION("packet was not removed properly...");
    if (!p)
        THROWEXCEPTION("packet is null");
#endif

    statTotalPacketsProcessed++;
    statTotalSegmentBytesProcessed += (p->net_total_length - p->payloadOffset);

    return p;
}

/**
 * Find a matching TCPStream for the passed Packet. If no matching TCPStream exists
 * a new one is created.
 * @param p the Packet to match against
 * @return a new or existing TCPStream matching the Packet
 */
TCPStream* TCPMonitor::findOrCreateStream(Packet* p) {
    TCPStream* ts = 0;
    StreamHashTable::iterator it = htable->find(TCPStream(p));

    if (it == htable->end()) {
        pair<hashtable<TCPStream>::iterator, bool> result = htable->insert_unique(*new TCPStream(p, streamCounter++));

        if (!result.second)
            THROWEXCEPTION("tcpmon: could not insert new TCPStream into hashtable");

        ts = &(*result.first);

        // initialize HTTP related data
        if (MAX_BUFFERED_BYTES_HTTP > 0)
            ts->httpData = HTTPAggregation::initHTTPStreamData(MAX_BUFFERED_BYTES_HTTP);
        else
            ts->httpData = HTTPAggregation::initHTTPStreamData();

        // update the pointer to the TCPStream::direction, so we can access
        // the current direction from other places like HttpAggregation
        ts->httpData->direction = &ts->direction;

        DPRINTFL(MSG_INFO, "tcpmon: created new stream with hash: %lu", hash_value(*ts));
        statConnections++;
#ifdef DEBUG
		ts->printKey();
#endif
    } else {
        ts =  &(*it);
        DPRINTFL(MSG_DEBUG,"tcpmon: found existing stream, with hash: %lu", hash_value(*ts));
#ifdef DEBUG
		ts->printKey();
#endif
    }

    return ts;
}

/**
 * Convenience function to refresh the timeout timestamp.
 * This function calls TCPStream::refreshTimeout(TCPStream*, TimeoutList& list, const uint32_t& timeout),
 * whith the proper parameters defined by the state of the TCPStream.
 * @param ts the TCPStream whose timeout timestamp should be refreshed
 */
void TCPMonitor::refreshTimeout(TCPStream* ts, bool refreshClosed)
{
    switch (ts->state) {
        case TCPStream::TCP_UNDEFINED:
        case TCPStream::TCP_ATTEMPT:
            refreshTimeout(ts, attemptedConnections, TIMEOUT_ATTEMPTED);
            break;
        case TCPStream::TCP_ESTABLISHED:
            refreshTimeout(ts, establishedConnections, TIMEOUT_ESTABLISHED);
            break;
        case TCPStream::TCP_CLOSED:
            // it should be better to not refresh closed connections
            if (refreshClosed) {
                refreshTimeout(ts, closedConnections, TIMEOUT_CLOSED);
            }
            break;
        default:
            THROWEXCEPTION("undefined TCPStream state");
            break;
    }
}

/**
 * Refreshes the timeout timestamp of a TCPStream. The new point in time at which
 * the TCPStream expires is calculated by adding a certain timeout to either the
 * current time or timestamp of the latest packet seen. Additional the TCPStream
 * is pushed to the end of the list which it belongs to. That way we keep stored
 * TCPStreams in order of their expiry.
 * @param ts the TCPStream whose timeout timestamp should be refreshed
 * @param list the list which the TCPStream belongs to
 * @param timeout the timeout value to be
 */
void TCPMonitor::refreshTimeout(TCPStream* ts, TimeoutList& list, const uint32_t& timeout)
{
    if (ts->timeoutHook.is_linked()) {
        TimeoutList::iterator it = list.iterator_to(*ts);
        list.erase(it);
    }
    if (ts->outOfBufferSpace) {
        // if we ran out of space we want to delete the stream as soon as possible,
        // for that reason we push it to the front of the queue.
        list.push_front(*ts);
    } else {
        if (usePCAPTimestamps)
            addToTime(ts->timeout, currentTimestamp, timeout);
        else
            addToCurTime(&ts->timeout, timeout);
        list.push_back(*ts);
    }
}

/**
 * Checks for expired streams and removes them
 * @param all If true all TCPStream instances are expired, otherwise only the expired ones. Default is false.
 */
void TCPMonitor::expireStreams(bool all) {
    timeval currentTime;
    if (usePCAPTimestamps)
        currentTime = currentTimestamp;
    else 
        gettimeofday(&currentTime, NULL);

    expireList(all, attemptedConnections, currentTime);
    expireList(all, establishedConnections, currentTime);
    expireList(all, closedConnections, currentTime);
}

/**
 * Checks for expired streams in @p list and removes them.
 * @param all If true all TCPStream instances maintained by @p list are expired, otherwise only the expired ones. Default is false.
 * @param list The list which should be checked
 * @param currentTime TCPStream instances whose timeout value is before or equal this point are expired
 */
void
TCPMonitor::expireList(bool all, TimeoutList& list, timeval compare) {
    TimeoutList::size_type before = list.size();
    TimeoutList::iterator it = list.begin();
    while (it != list.end()) {
        TCPStream* ts = &(*it);
        if (all || ts->outOfBufferSpace || compareTime(ts->timeout, compare) <= 0) {
            if (ts->state != TCPStream::TCP_CLOSED)
                ts->addAnnotationFlag(FlowAnnotation::TCP_CON_EXPIRED);
            DPRINTFL(MSG_DEBUG, "tcpmon: expiring stream with hash: %lu", hash_value(*ts));
            // release all Packets queued for this TCPStream
            ts->releaseQueuedPackets();
            // remove the TCPStream instance from the TimeoutList
            it = list.erase(it);
            // remove the TCPStream from the hashtable
            htable->erase(*ts);
            // finally free all memory used
            delete ts;
        }
        else {
#ifdef DEBUG
            timeval diff, x = ts->timeout, y = compare;
            timeval_subtract(&diff, &x, &y);
            msg(MSG_VDEBUG, "tcpmon: not expiring %lu, still %lu ms remaining", hash_value(*ts),  diff.tv_sec*1000 + diff.tv_usec/1000);
            it++;
#else
            // we don't have to check all the entries in the list as they are stored in order of expiry.
            // so we can stop when we reach the first TCPStream which does not expire yet
            break;
#endif
        }
    }

    if (list.size() != before) {
        string name;
        TimeoutList::size_type diff = before - list.size();
        if (&list == &establishedConnections) {
            statTotalExpiredEstablishedConnections += diff;
            name = "established";
        }
        else if (&list == &closedConnections) {
            statTotalExpiredClosedConnections += diff;
            name = "closed";
        }
        else if (&list == &attemptedConnections) {
            statTotalExpiredConnectionsAttempts += diff;
            name = "attempted";
        }
        DPRINTFL(MSG_DEBUG, "tcpmon: expired %lu %s stream(s)", diff,  name.c_str());
    }

#ifdef DEBUG
    TimeoutList::iterator it2 = list.begin();
    while (it2 != list.end()) {
        TCPStream* ts = &(*it2);
        if (compareTime(ts->timeout, compare) <= 0) {
            THROWEXCEPTION("expireList() encountered an error, an expired TCP stream has not been exported.");
        }
        it2++;
    }
#endif
}

/**
 * Changes the state of the TCPStream and moves the TCPStream to the proper timeout list
 * @param ts TCPStream which should be updated
 * @param newState the new State of the TCPStream
 * @param regular specifies if a connection has been established regular (TCP-handshake)
 */
void TCPMonitor::changeState(TCPStream* ts, TCPStream::tcp_state_t newState, bool regular) {
    if (ts->state >= newState)
        return;

    switch (newState) {
        case TCPStream::TCP_ATTEMPT:
            statAttemptedConnections++;
            break;
        case TCPStream::TCP_ESTABLISHED:
            statEstablishedConnections++;
            if (regular && ts->state == TCPStream::TCP_ATTEMPT) {
                statTotalRegularEstablishedConnections++;
            } else {
                statTotalNonRegularEstablishedConnections++;
            }
            break;
        case TCPStream::TCP_CLOSED:
            statClosedConnections++;
            break;
        default:
            THROWEXCEPTION("invalid list/state change requested");
    }

    TimeoutList& from = getList(ts->state);
    TimeoutList& to = getList(newState);


    ts->state = newState;
    changeList(ts, from, to);
}

/**
 * Returns the list which corresponds to the given state
 * @param state
 * @return
 */
TimeoutList& TCPMonitor::getList(TCPStream::tcp_state_t state) {
    switch (state) {
        case TCPStream::TCP_UNDEFINED:
        case TCPStream::TCP_ATTEMPT:
            return attemptedConnections;
            break;
        case TCPStream::TCP_ESTABLISHED:
            return establishedConnections;
            break;
        case TCPStream::TCP_CLOSED:
            return closedConnections;
            break;
    }
    THROWEXCEPTION("undefined TCPStream state");
}

/**
 * Moves a TCPStream from a list to the specified list
 * timeout accordingly.
 * @param ts TCPStream to move
 * @param from source list from which the TCPStream should be removed
 * @param to destination list in which the TCPStream should be inserted
 */
void TCPMonitor::changeList(TCPStream* ts, TimeoutList& from, TimeoutList& to) {
    if (ts->timeoutHook.is_linked()) {
        TimeoutList::iterator it = from.iterator_to(*ts);
        from.erase(it);
    }
    refreshTimeout(ts, true);
}

/**
 * Check flags against a bitmask
 * @param flags
 * @param bitmask
 * @return
 */
bool TCPMonitor::isSet(uint8_t flags, uint8_t bitmask) {
    return ((flags & bitmask) ^ bitmask) == 0;
}

/**
 * Performs a conservative check to determine if a given TCP sequence number should be
 * considered as fresh or not, relative to the passed TCPData::nextSeq. Fresh TCP
 * sequence numbers are new and unseen sequence numbers. Non fresh sequence numbers are
 * sequence numbers which should already have been seen.
 * The fact that TCP sequence numbers can wrap around complexes this check, because
 * we cannot simply check @p TCPData::nextSeq < @p seq.
 * Therefore the sequence number space 2^32 is divided in two equal parts, starting from
 * TCPData::nextSeq. If @p is in the range 2^31 starting from TCPData::nextSeq+1 it is
 * considered as fresh, otherwise it is considered as not fresh.
 *
 * TODO implement TCP PAWS (Protection Against Wrapped Sequence numbers) from RFC 1323
 *
 * @param seq TCP sequence number to check
 * @param ts TCPData which supplies a reference to check against
 * @return the difference between the two sequence numbers in bytes if the TCP sequence number is considered as fresh, 0 otherwise.
 */
uint32_t TCPMonitor::isFresh(uint32_t seq, TCPData& td) {
    int seqDiff = (int) (seq - td.nextSeq);

    return seqDiff > 0 ? seqDiff : 0;
}

void TCPMonitor::printStreamCount() {
    msg(MSG_VDEBUG, "total streams: %lu, stream attempts: %lu, established streams: %lu, closed streams: %lu, stream counter: %u", htable->size(), attemptedConnections.size(), establishedConnections.size(), closedConnections.size(), streamCounter);
}

int TCPMonitor::IN_ORDER     = 0;
int TCPMonitor::OUT_OF_ORDER = 1;
int TCPMonitor::CLOSED       = 2;

// statistics
uint64_t TCPMonitor::statConnections;
uint64_t TCPMonitor::statTotalConnections;
uint64_t TCPMonitor::statAttemptedConnections;
uint64_t TCPMonitor::statTotalAttemptedConnections;
uint64_t TCPMonitor::statEstablishedConnections;
uint64_t TCPMonitor::statTotalEstablishedConnections;
uint64_t TCPMonitor::statClosedConnections;
uint64_t TCPMonitor::statTotalClosedConnections;
uint64_t TCPMonitor::statTotalPackets;
uint64_t TCPMonitor::statTotalPacketsProcessed;
uint64_t TCPMonitor::statTotalSegmentBytes;
uint64_t TCPMonitor::statTotalSegmentBytesProcessed;
uint64_t TCPMonitor::statTotalTruncatedPackets;
uint64_t TCPMonitor::statTotalOutOfOrderPackets;
uint64_t TCPMonitor::statTotalBufferedPackets;
uint64_t TCPMonitor::statBufferedPackets;
uint64_t TCPMonitor::statTotalSkippedGaps;
uint64_t TCPMonitor::statTotalSkippedBytes;
uint64_t TCPMonitor::statTotalSkippedBufferedPackets;
uint64_t TCPMonitor::statTotalSkippedPacketsInGaps;
uint64_t TCPMonitor::statTotalBufferOverflows;
uint64_t TCPMonitor::statTotalRegularEstablishedConnections;
uint64_t TCPMonitor::statTotalNonRegularEstablishedConnections;
uint64_t TCPMonitor::statTotalExpiredConnectionsAttempts;
uint64_t TCPMonitor::statTotalExpiredEstablishedConnections;
uint64_t TCPMonitor::statTotalExpiredClosedConnections;
uint64_t TCPMonitor::statTotalTerminatedConnections;
uint64_t TCPMonitor::statTotalResettedConnections;
uint64_t TCPMonitor::statTotalHalfEstablishedConnections;
uint64_t TCPMonitor::statTotalInvalidPackets;

uint64_t TCPMonitor::statSamplesCount;

std::string TCPMonitor::getStatisticsXML(double interval)
{

    statSamplesCount++;
    statTotalConnections += statConnections;
    statTotalAttemptedConnections += statAttemptedConnections;
    statTotalEstablishedConnections += statEstablishedConnections;
    statTotalClosedConnections += statClosedConnections;

    ostringstream oss;
    oss << "\n";
    oss << "\t\t\t\t" << "<Connections>" << statConnections << "</Connections>" << "\n";
    oss << "\t\t\t\t" << "<AttemptedConnections>" << statAttemptedConnections << "</AttemptedConnections>" << "\n";
    oss << "\t\t\t\t" << "<EstablishedConnections>" << statEstablishedConnections << "</EstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<ClosedConnections>" << statClosedConnections << "</ClosedConnections>" << "\n";

    oss << "\t\t\t\t" << "<ActiveConnections>" << htable->size() << "</ActiveConnections>" << "\n";
    oss << "\t\t\t\t" << "<ActiveAttemptedConnections>" << attemptedConnections.size() << "</ActiveAttemptedConnections>" << "\n";
    oss << "\t\t\t\t" << "<ActiveEstablishedConnections>" << establishedConnections.size() << "</ActiveEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<ActiveClosedConnections>" << closedConnections.size() << "</ActiveClosedConnections>" << "\n";

    oss << "\t\t\t\t" << "<AvgConnections>" << statTotalConnections/(statSamplesCount) << "</AvgConnections>" << "\n";
    oss << "\t\t\t\t" << "<AvgAttemptedConnections>" << statTotalAttemptedConnections/(statSamplesCount) << "</AvgAttemptedConnections>" << "\n";
    oss << "\t\t\t\t" << "<AvgEstablishedConnections>" << statTotalEstablishedConnections/(statSamplesCount) << "</AvgEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<AvgClosedConnections>" << statTotalClosedConnections/(statSamplesCount) << "</AvgClosedConnections>" << "\n";

    oss << "\t\t\t\t" << "<TotalConnections>" << statTotalConnections << "</TotalConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalEstablishedConnections>" << statTotalEstablishedConnections << "</TotalEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalHalfEstablishedConnections>" << statTotalHalfEstablishedConnections << "</TotalHalfEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalRegularEstablishedConnections>" << statTotalRegularEstablishedConnections << "</TotalRegularEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalNonRegularEstablishedConnections>" << statTotalNonRegularEstablishedConnections << "</TotalNonRegularEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalTerminatedConnections>" << statTotalTerminatedConnections << "</TotalTerminatedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalResettedConnections>" << statTotalResettedConnections << "</TotalResettedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalInvalidPackets>" << statTotalInvalidPackets << "</TotalInvalidPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalExpiredConnectionsAttempts>" << statTotalExpiredConnectionsAttempts << "</TotalExpiredConnectionsAttempts>" << "\n";
    oss << "\t\t\t\t" << "<TotalExpiredEstablishedConnections>" << statTotalExpiredEstablishedConnections << "</TotalExpiredEstablishedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalExpiredClosedConnections>" << statTotalExpiredClosedConnections << "</TotalExpiredClosedConnections>" << "\n";
    oss << "\t\t\t\t" << "<TotalPackets>" << statTotalPackets << "</TotalPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalPacketsProcessed>" << statTotalPacketsProcessed << "</TotalPacketsProcessed>" << "\n";
    oss << "\t\t\t\t" << "<TotalSegmentBytes>" << statTotalSegmentBytes << "</TotalSegmentBytes>" << "\n";
    oss << "\t\t\t\t" << "<TotalSegmentBytesProcessed>" << statTotalSegmentBytesProcessed << "</TotalSegmentBytesProcessed>" << "\n";
    oss << "\t\t\t\t" << "<TotalTruncatedPackets>" << statTotalTruncatedPackets << "</TotalTruncatedPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalOutOfOrderPackets>" << statTotalOutOfOrderPackets << "</TotalOutOfOrderPackets>" << "\n";
    oss << "\t\t\t\t" << "<BufferedOutOfOrderPackets>" << statBufferedPackets << "</BufferedOutOfOrderPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalBufferedOutOfOrderPackets>" << statTotalBufferedPackets << "</TotalBufferedOutOfOrderPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalSkippedGaps>" << statTotalSkippedGaps << "</TotalSkippedGaps>" << "\n";
    oss << "\t\t\t\t" << "<TotalSkippedBytes>" << statTotalSkippedBytes << "</TotalSkippedBytes>" << "\n";
    oss << "\t\t\t\t" << "<TotalSkippedBufferedPackets>" << statTotalSkippedBufferedPackets << "</TotalSkippedBufferedPackets>" << "\n";
    oss << "\t\t\t\t" << "<TotalSkippedPacketsInGaps>" << statTotalSkippedPacketsInGaps << "</TotalSkippedPacketsInGaps>" << "\n";
    oss << "\t\t\t\t" << "<TotalBufferOverflows>" << statTotalBufferOverflows << "</TotalBufferOverflows>" << "\n";
    oss << "\t\t\t";

    // reset counters
    statBufferedPackets = 0;
    statConnections = 0;
    statAttemptedConnections = 0;
    statEstablishedConnections = 0;
    statClosedConnections = 0;

    return oss.str();
}

