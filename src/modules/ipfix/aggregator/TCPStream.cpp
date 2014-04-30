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

TCPStream::TCPStream(Packet* p, uint32_t num) : streamNum(num), direction(FORWARD), state(TCPStream::TCP_UNDEFINED), httpData(0), truncatedPackets(false), bufferedSize(0) {
    // values are stored in network byte order since the values are only used for calculating the hash
    hkey.srcIp = *reinterpret_cast<uint32_t*>(p->data.netHeader + OFFSET_SRC_IP);       // source IP
    hkey.dstIp = *reinterpret_cast<uint32_t*>(p->data.netHeader + OFFSET_DST_IP);       // destination IP
    hkey.srcPort = *reinterpret_cast<uint16_t*>(p->transportHeader + OFFSET_SRC_PORT);  // source port
    hkey.dstPort = *reinterpret_cast<uint16_t*>(p->transportHeader + OFFSET_DST_PORT);  // destination port
}

TCPStream::~TCPStream() {
    if (!httpData)
        return;
    if (httpData->forwardLine)
        free(httpData->forwardLine);
    if (httpData->reverseLine)
        free(httpData->reverseLine);
    delete httpData;
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
 * Releases all queued packets from the TCPStream::packetQueue.
 */
void TCPStream::releaseQueuedPackets() {
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
    packetQueue.clear();
    bufferedSize = 0;
}

/**
 * Prints the TCPStream::hkey in a human readable format (network 4-tuple)
 */
void TCPStream::printKey() {
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &hkey.srcIp, srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &hkey.dstIp, dstIp, INET_ADDRSTRLEN);
    DPRINTFL(MSG_DEBUG, "tcpmon: src ip=%s port=%d, dst ip=%s port=%d", srcIp, ntohs(hkey.srcPort), dstIp, ntohs(hkey.dstPort));
}

void TCPStream::printQueueStats() {
    msg(MSG_ERROR, "tcpmon: queued packets: %lu", packetQueue.size());
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

TCPMonitor::TCPMonitor(uint32_t htableSize, uint32_t timeoutOpened, uint32_t timeoutClosed, uint32_t maxBufferedBytes, uint32_t maxBufferedBytesHTTP) :
        streamCounter(0) {
    // initialize 'htableSize' buckets for the hashtable
    base_buckets = new StreamHashTable::bucket_type[htableSize];
    // initialize the hashtable
    htable = new StreamHashTable(StreamHashTable::bucket_traits(base_buckets, htableSize));
    TIMEOUT_OPENED = timeoutOpened ? timeoutOpened : DEF_TIMEOUT_OPENED;
    TIMEOUT_CLOSED = timeoutClosed ? timeoutClosed : DEF_TIMEOUT_CLOSED;
    MAX_BUFFERED_BYTES = maxBufferedBytes ? maxBufferedBytes : DEF_TCP_BUFFER_SIZE;
    MAX_BUFFERED_BYTES_HTTP = maxBufferedBytesHTTP ? maxBufferedBytes : HTTPAggregation::DEF_MAX_BUFFERED_BYTES;
    msg(MSG_INFO, "tcpmon: Instantiated TCPMonitor with timeoutOpened: %u ms and timeoutClosed: %u ms. Hashtablebucket size: %d. TCP buffer size: %u bytes. HTTP message buffer size: %u bytes",
            TIMEOUT_OPENED, TIMEOUT_CLOSED, htableSize, MAX_BUFFERED_BYTES, MAX_BUFFERED_BYTES_HTTP);
    SensorManager::getInstance().addSensor(this, "TCPMonitor", 0);
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
TCPStream* TCPMonitor::dissect(Packet* p) {
    statTotalPackets++;
    TCPStream* ts = findOrCreateStream(p);

    if (p->pcapPacketLength > p->data_length_uncropped) {
        statTruncatedPackets++;
        if (!ts->truncatedPackets) {
            ts->truncatedPackets = true;
            msg(MSG_ERROR, "tcpmon: WARNING, this TCP connection contains truncated packets");
        }
    }

    // update the timeout timestamp of the TCPStream
    refreshTimeout(ts);

    // if the TCP stream was closed before we do not have to consider this Packet
    if (ts->state == TCPStream::TCP_CLOSED) {
        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet, TCP connection was closed before");
        // remove the reference to the Packet instance
        p->removeReference();
        statSkippedPackets++;
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if (refCount != 1)
        THROWEXCEPTION("wrong reference count: %d. expected: 1", refCount);
#endif
        return NULL;
    }

    ts->updateDirection(p);

    // perform TCP connection analysis
    if (!analysePacket(p, ts)) {
        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet, packet is out of order.");
        return NULL;
    }

    if (ts->state == TCPStream::TCP_CLOSED) {
        DPRINTFL(MSG_DEBUG, "tcpmon: skipping packet, TCP connection is closed");
        // remove the reference to the Packet instance
        p->removeReference();
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if (refCount != 1)
        THROWEXCEPTION("wrong reference count: %d. expected: 1", refCount);
#endif
        return NULL;
    }

    return ts;
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
    TCPData* src = ts->isForward() ? &ts->fwdData : &ts->revData;
    // TCPData from the destination of the Packet
    TCPData* dst = ts->isReverse() ? &ts->fwdData : &ts->revData;

    uint32_t slen = p->net_total_length - p->payloadOffset; // TCP segment length

    DPRINTFL(MSG_DEBUG, "tcpmon: seq#: %u, is next:%s, ack#: %u, flags: SYN=%d, ACK=%d, FIN=%d, RST=%d, plen: %u, slen:%u",
            seq, seq == src->nextSeq ? "yes":"no", ack, (bool)(flags&FLAG_SYN), (bool)(flags&FLAG_ACK), (bool)(flags&FLAG_FIN), (bool)(flags&FLAG_RST), p->pcapPacketLength, slen);

    if (isSet(flags, FLAG_SYN | FLAG_FIN) || isSet(flags, FLAG_SYN | FLAG_RST)) {
        msg(MSG_ERROR, "tcpmon: dropping a packet with an illegal combination of TCP flags: : SYN=%d, ACK=%d, FIN=%d, RST=%d",
                (bool)(flags&FLAG_SYN), (bool)(flags&FLAG_ACK), (bool)(flags&FLAG_FIN), (bool)(flags&FLAG_RST));
        if (ts->state != TCPStream::TCP_CLOSED) {
              // move TCPStream to the TimoutList closedStreams
              changeList(ts);
              // clear all cached packets. after the connection close all further
              // packets are rejected.
              ts->releaseQueuedPackets();
          }
          ts->state = TCPStream::TCP_CLOSED;
    } else if (isSet(flags, FLAG_SYN) && !isSet(flags, FLAG_ACK) && src->initSeq==0 && src->initSeq != seq) {
        // this is a connection attempt, i.e. a SYN packet
        DPRINTFL(MSG_INFO, "tcpmon: TCP handshake: connection attempt (SYN)");
        src->initSeq = seq;
        src->nextSeq = seq + 1;
    } else if (isSet(flags, FLAG_SYN | FLAG_ACK) && src->initSeq==0 && src->initSeq != seq && dst->initSeq + 1 == ack) {
        // this is a connection established, i.e. a SYN+ACK packet
        DPRINTFL(MSG_INFO, "tcpmon: TCP handshake: connection established (SYN+ACK)");
        src->initSeq = seq;
        src->nextSeq = seq + 1;
        ts->state = TCPStream::TCP_ESTABLISHED;
        statTotalConnections++;
        statRegularEstablishedConnections++;
    } else if (isSet(flags, FLAG_FIN) && src->seqFin == 0 && src->nextSeq == seq) {
        if (dst->seqFin==0) {
            // one party requests to close the connection
            DPRINTFL(MSG_INFO, "tcpmon: TCP termination: closing connection");
        }
        else {
            // the other party also wants to close the connection,
            // so the TCP termination can be considered as complete
            DPRINTFL(MSG_INFO, "tcpmon: TCP termination: connection closed");
            if (ts->state != TCPStream::TCP_CLOSED) {
                // move TCPStream to the TimoutList closedStreams
                changeList(ts);
                // clear all cached packets. after the connection close all further
                // packets are rejected.
                ts->releaseQueuedPackets();
            }
            ts->state = TCPStream::TCP_CLOSED;
        }
        src->nextSeq = seq + 1;
        src->seqFin = seq;
    } else if (isSet(flags, FLAG_RST)) {
        // discovered a RST packet, immediately close the connection
        DPRINTFL(MSG_INFO, "tcpmon: TCP RST discovered: connection closed");
        if (ts->state != TCPStream::TCP_CLOSED) {
            // move TCPStream to the TimoutList closedStreams
            changeList(ts);
            // clear all cached packets. after the connection close all further
            // packets are rejected.
            ts->releaseQueuedPackets();
        }
        ts->state = TCPStream::TCP_CLOSED;
        src->nextSeq = seq + 1;
        src->seqFin = seq;
    } else if (src->nextSeq == seq) {
        // this data packet is in order, update next sequence number
        DPRINTFL(MSG_DEBUG, "tcpmon: ordinary data packet, setting next seq nr to %u", seq + slen);
        src->nextSeq = seq + slen;
    } else {
        if (src->initSeq == 0 && src->nextSeq == 0) {
            // for some reason we did not discover the initial sequence number.
            // guess the initial sequence number equals actual seq - 1
            src->initSeq = seq - 1;
            src->nextSeq = seq + slen;
            ts->state = TCPStream::TCP_ESTABLISHED;
            statTotalConnections++;
            statNonRegularEstablishedConnections++;
            DPRINTFL(MSG_INFO, "tcpmon: TCP new connection established (handshake was not observed)");
        } else if (src->nextSeq) {
            if (isFresh(seq, src)) {
                // this is a new unseen packet which is out-of-order
                statOutOfOrderPackets++;
                PacketQueue::iterator it = ts->packetQueue.find(PacketQueue::key_type(seq));
                if (it == ts->packetQueue.end()) {
                    if (ts->bufferedSize + p->pcapPacketLength > MAX_BUFFERED_BYTES) {
                        statBufferOverflows++;
                        msg(MSG_ERROR, "tcpmon: out of buffer space! cannot proceed with TCP reassembly for stream with hash %lu.", hash_value(*ts));
                        if (ts->state != TCPStream::TCP_CLOSED) {
                            // move TCPStream to the TimoutList closedStreams
                            changeList(ts);
                            // clear all cached packets. after the connection close all further
                            // packets are rejected.
                            ts->releaseQueuedPackets();
                        }
                        ts->state = TCPStream::TCP_CLOSED;
                        p->removeReference();
                        return false;
                    }
                    statBufferedOutOfOrderPackets++;
                    ts->packetQueue.insert(PacketQueue::value_type(seq, p));
                    DPRINTFL(MSG_DEBUG, "tcpmon: non contiguous sequence number. inserting packet with seq# %u into PacketQueue for later processing.", seq);
                    ts->bufferedSize += p->pcapPacketLength;
                }
            } else {
                // this packet has been seen previously and should not have to be processed
                DPRINTFL(MSG_INFO, "tcpmon: packet is out of order. not considering packet because the sequence number should already have been processed.");
                p->removeReference();
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if (refCount != 1)
        THROWEXCEPTION("wrong reference count: %d. expected: 1", refCount);
#endif
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
 * Check if the TCPStream contains queued Packets which can be processed.
 * If a Packet is in order, i.e. the sequence number matches the next expected
 * in the current direction TCPData::nextSeq, the Packet is returned.
 * @param ts TCPStream which should be checked
 * @return The next queued Packet in order, or NULL if no Packet was queued which is in order.
 */
Packet* TCPMonitor::nextPacketForStream(TCPStream* ts) {
    // lookup for a queued Packet which is in order
    TCPData* src = ts->isForward() ? &ts->fwdData : &ts->revData;
    uint32_t nseq = src->nextSeq;
    PacketQueue::iterator it = ts->packetQueue.find(nseq);
    if (it == ts->packetQueue.end()) {
        return NULL;
    }

    Packet* p = (*it).second;
    DPRINTFL(MSG_INFO, "tcpmon: processing queued packet with sequence number: %u", nseq);

    // delete the Packet from the queue
    ts->packetQueue.erase(it);
    ts->bufferedSize -= p->pcapPacketLength;

#ifdef DEBUG
    uint32_t seq = ntohl(*reinterpret_cast<uint32_t*>(p->transportHeader + OFFSET_SEQ));
    if (seq != nseq)
        THROWEXCEPTION("sequence number of stored packet does not match.");
#endif

    // perform TCP analysis
    bool result = analysePacket(p, ts);

    if (ts->state == TCPStream::TCP_CLOSED) {
        // remove the reference to the Packet instance
        p->removeReference();
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if (refCount != 0)
        THROWEXCEPTION("wrong reference count: %d. expected: 0", refCount);
#endif
        return NULL;
    }

#ifdef DEBUG
    if (ts->packetQueue.find(nseq)!=ts->packetQueue.end())
        THROWEXCEPTION("packet was not removed properly...");
    if (!result)
        THROWEXCEPTION("packet was inserted twice");
    if (!p)
        THROWEXCEPTION("packet is null");
#endif

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
 * Refreshes the timeout timestamp of a TCPStream. The new point in time at which
 * the TCPStream expires is calculated by adding a certain timeout to the current
 * time. Depending on the state of the TCP connection either ::TIMEOUT_CLOSED or
 * ::TIMEOUT_OPENED is added. Additional the TCPStream is pushed to the end of the
 * list which it belongs to. That way we keep stored TCPStreams in order of their
 * expiry.
 */
void TCPMonitor::refreshTimeout(TCPStream* ts)
{
    if ( ts->state == TCPStream::TCP_CLOSED) {
        if (ts->timeoutHook.is_linked()) {
            TimeoutList::iterator it = closedStreams.iterator_to(*ts);
            closedStreams.erase(it);
        }
        addToCurTime(&ts->timeout, TIMEOUT_CLOSED);
        closedStreams.push_back(*ts);
    } else {
        if (ts->timeoutHook.is_linked()) {
            TimeoutList::iterator it = openedStreams.iterator_to(*ts);
            openedStreams.erase(it);;
        }
        addToCurTime(&ts->timeout, TIMEOUT_OPENED);
        openedStreams.push_back(*ts);
    }
}

/**
 * Checks for expired streams and removes them
 * @param all If true all TCPStream instances are expired, otherwise only the expired ones. Default is false.
 */
void TCPMonitor::expireStreams(bool all) {
    timeval currentTime;
    gettimeofday(&currentTime, NULL);
    expireList(all, openedStreams, currentTime);
    expireList(all, closedStreams, currentTime);
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
        if (all || compareTime(ts->timeout, compare) <= 0) {
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
            DPRINTFL(MSG_VDEBUG, "tcpmon: not expiring, still %lu ms remaining", diff.tv_sec*1000 + diff.tv_usec/1000);
            it++;
#else
            // we don't have to check all the entries in the list as they are stored in order of expiry.
            // so we can stop when we reach the first TCPStream which does not expire yet
            break;
#endif
        }
    }

    if (list.size() != before) {
        TimeoutList::size_type diff = before - list.size();
        DPRINTFL(MSG_DEBUG, "tcpmon: expired %lu %s streams", diff,  &list == &openedStreams ? "open" : "closed");
        if (&list == &openedStreams)
            statExpiredOpenConnections += diff;
        else
            statExpiredClosedConnections += diff;
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
 * Moves a TCPStream from ::openStreams to ::closedStreams and sets the
 * timeout accordingly.
 * @param ts TCPStream to move
 */
void TCPMonitor::changeList(TCPStream* ts) {
    if (ts->timeoutHook.is_linked()) {
        TimeoutList::iterator it = openedStreams.iterator_to(*ts);
        openedStreams.erase(it);
    }
    addToCurTime(&ts->timeout,TIMEOUT_CLOSED);
    closedStreams.push_back(*ts);
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
 * @return true if the TCP sequence number is considered as fresh, false otherwise.
 */
bool TCPMonitor::isFresh(uint32_t seq, TCPData* td) {
    uint32_t MAX_HALF = 0x7FFFFFFF;
    if (td->nextSeq < seq && seq - td->nextSeq < MAX_HALF)
        return true;
    if (td->nextSeq > seq && td->nextSeq - seq > MAX_HALF)
        return true;
    return false;
}

void TCPMonitor::printStreamCount() {
    msg(MSG_ERROR, "total streams: %lu, open streams: %lu, closed streams: %lu, stream counter: %u", htable->size(), openedStreams.size(), closedStreams.size(), streamCounter);
}

std::string TCPMonitor::getStatisticsXML(double interval)
{
    ostringstream oss;
    oss << "<TotalConnections>" << statTotalConnections << "</TotalConnections>";
    oss << "<TotalPackets>" << statTotalPackets << "</TotalPackets>";
    oss << "<TruncatedPackets>" << statTruncatedPackets << "</TruncatedPackets>";
    oss << "<OutOfOrderPackets>" << statOutOfOrderPackets << "</OutOfOrderPackets>";
    oss << "<BufferedOutOfOrderPackets>" << statBufferedOutOfOrderPackets << "</BufferedOutOfOrderPackets>";
    oss << "<SkippedPackets>" << statSkippedPackets << "</SkippedPackets>";
    oss << "<BufferOverflows>" << statBufferOverflows << "</BufferOverflows>";
    oss << "<ExpiredOpenConnections>" << statExpiredOpenConnections << "</ExpiredOpenConnections>";
    oss << "<ExpiredClosedConnections>" << statExpiredClosedConnections << "</ExpiredClosedConnections>";
    oss << "<RegularEstablishedConnections>" << statRegularEstablishedConnections << "</RegularEstablishedConnections>";
    oss << "<NonRegularEstablishedConnections>" << statNonRegularEstablishedConnections << "</NonRegularEstablishedConnections>";

    return oss.str();
}

