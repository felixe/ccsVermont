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

#ifndef TCPSTREAM_H
#define TCPSTREAM_H

#include "HTTPAggregation.h"
#include "common/Time.h"
#include <boost/intrusive/list.hpp>
#include <boost/intrusive/hashtable.hpp>
#include <boost/intrusive/unordered_set_hook.hpp>
#include <map>
#include <sys/time.h>
#include <arpa/inet.h>

static const uint8_t FORWARD = 0; /**< the packet comes from the originator of the TCP connection */
static const uint8_t REVERSE = 1; /**< the packet comes from the destination of the TCP connection */

static const int OFFSET_SRC_IP = 12;    /**< source IP address offset in the raw packet, relative to the net header */
static const int OFFSET_DST_IP = 16;    /**< destination IP address offset in the raw packet, relative to the net header */
static const int OFFSET_SRC_PORT = 0;   /**< source port offset in the raw packet, relative to the transport header */
static const int OFFSET_DST_PORT = 2;   /**< destination port offset in the raw packet, relative to the transport header */
static const int OFFSET_SEQ = 4;        /**< sequence number offset in the raw packet, relative to the transport header */
static const int OFFSET_ACK = 8;        /**< acknowledgment number raw packet, relative to the transport header */
static const int OFFSET_FLAGS = 13;     /**< source port offset in the raw packet, relative to the transport header */

static const int FLAG_FIN = 0x01;   /**< TCP FIN flag */
static const int FLAG_SYN = 0x02;   /**< TCP SYN flag */
static const int FLAG_RST = 0x04;   /**< TCP RST flag */
static const int FLAG_ACK = 0x10;   /**< TCP ACK flag */

static const uint32_t DEF_TIMEOUT_OPENED = 30000; /**< Default expiry timeout in ms a TCP stream may remain idle before expiring. */
static const uint32_t DEF_TIMEOUT_CLOSED =  2000; /**< Default expiry timeout in ms that is kept after connection close before expiring. */

static const uint32_t DEF_TCP_BUFFER_SIZE = 1024 * 1024; /**< Default TCP buffer size for buffering out-of-order segments is defined as 1 MiB */

using namespace boost;
using namespace boost::intrusive;

/**
 * This structure helps to keep track of the packet order and status of a TCP connection
 */
struct TCPData {
    uint32_t initSeq;   /**< Initial sequence number (ISN) of a connection */
    uint32_t seqFin;    /**< Last (relevant) sequence number of a connection */
    uint32_t nextSeq;   /**< Next sequence number in order */
    TCPData() : initSeq(0), seqFin(0), nextSeq(0) {}
};

//! map sequence numbers to packets
typedef std::map<uint32_t, Packet*> PacketQueue;

/**
 * Representation of a TCP connection.
 * Instances of this class are inserted into the hashtable TCPMonitor::htable
 * in the TCPMonitor, which keeps track of registered TCP streams.
 * The hook for the hashtable is publicly derived from unordered_set_base_hook.
 * Moreover TCPStreams are inserted into lists to control their expiry.
 * The public member TCPStream::timeoutHook is used for that reason.
 */
class TCPStream : public unordered_set_base_hook<> {
public:
    TCPStream(Packet* p, uint32_t num = 0);
    ~TCPStream();

    //! information about state of a TCP connection
    typedef enum tcp_state {
        TCP_UNDEFINED,      /**< TCP connection did not start yet */
        TCP_ESTABLISHED,    /**< TCP connection has been established*/
        TCP_CLOSED          /**< TCP connection was closed */
    } tcp_state_t;

    //! hash key type
    /*! The key also defines the two directions of a stream, #FORWARD and #REVERSE.
     * Packets from the source IP and port to the destination IP and port are in #FORWARD direction,
     * whereas packets from destination IP and port to source IP and port are in #REVERSE direction.*/
    struct hkey_t {
        uint32_t srcIp;     /**< Source IP address in network byte order */
        uint32_t dstIp;     /**< Destination IP address in network byte order */
        uint16_t srcPort;   /**< Source Port in network byte order */
        uint16_t dstPort;   /**< Destination Destination in network byte order */
    } hkey;

    uint32_t streamNum; /**< Internal identifier used for hashing in the PacketHashtable */
    uint8_t direction;  /**< Direction of the stream, can be #FORWARD or #REVERSE.
                             This field is updated whenever a packet of this TCP connection arrives or
                             is processed. The first packet observed determines the source and
                             destination of a flow, as the TCPStream::hkey is set upon TCPStream
                             instantiation. */
    tcp_state_t state;  /**< Holds the state of the TCP connection */
    HTTPAggregation::HTTPStreamData* httpData;    /**< A pointer to HTTP related information */

    TCPData fwdData;    /**< TCP data in forward direction */
    TCPData revData;    /**< TCP data in reverse direction */

    PacketQueue packetQueue;    /**< Packets which are not in order are stored in this map for later processing */
    uint32_t bufferedSize;      /**< The number of buffered bytes of all packets in the queue */

    timeval timeout;    /**< Timestamp at which this TCPStream expires */
    list_member_hook<> timeoutHook; /**< Public member hook which allows to put this class into a boost::intrusive::list */

    bool truncatedPackets;  /**< set to true if a truncated packet was observed to be part of this stream */

    bool isForward();
    bool isReverse();
    void updateDirection(Packet* p);
    void releaseQueuedPackets();
    void printKey();
    void printQueueStats();
};

//! ordered list of TCPStreams
typedef boost::intrusive::list<TCPStream
            , member_hook<TCPStream, list_member_hook<>, &TCPStream::timeoutHook>
            > TimeoutList;

typedef boost::intrusive::hashtable<TCPStream> StreamHashTable;

/**
 * Monitors and manages TCP connections and performs TCP stream reassembly.
 *
 * This class allows to monitor TCP streams aka TCP connections. TCP connections
 * are represented by the class TCPStream. Once a new TCP connection is observed
 * a new TCPStream instance is created and is stored within a hashtable, which
 * allows for fast lookup and insertion.
 * Further this class provides basic TCP stream reassembly functionality. Packets
 * are analyzed and ordered properly.
 *
 * A call to the method TCPMonitor::dissect(Packet* p) analyzes a Packet
 * and returns the TCPStream representing the TCP connection, which the packet
 * belongs to. If a packet is not in order it is queued for later processing.
 * The method TCPMonitor::nextPacketForStream(TCPStream*) returns those
 * queued packets in order, as long as the TCP segments are contiguous. With
 * expireStreams() it is possible to expire either streams which have reached
 * their timeout value or all streams.
 *
 * To control the timeout of the TCPStream instances, two lists are maintained. Each
 * of those stores a set of TCPStreams ordered by their expiry.
 * As long as a TCP connection is active, pertaining Packets refresh the timeout
 * timestamp. Once a TCP connection is considered as closed, this timestamp is
 * refreshed for the last time. The timeout value for active TCP streams is bigger
 * than the one for closed TCP streams. For that reason two different "timeout" lists
 * are maintained. Whenever a TCPStream belonging to either of these lists
 * is "refreshed" or inserted, it is pushed to the end of the proper list. That way
 * all the TCPStreams managed by the list are stored in order of their expiry. Which
 * makes the access faster and easier.
 */
class TCPMonitor {
public:
    TCPMonitor(uint32_t htableSize, uint32_t timeoutOpened, uint32_t timeoutClosed, uint32_t maxBufferedBytes, uint32_t maxBufferedBytesHTTP);
    ~TCPMonitor();
    TCPStream* dissect(Packet* p);
    Packet* nextPacketForStream(TCPStream* ts);
    void expireStreams(bool all = false);
    void printStreamCount();

private:
    bool analysePacket(Packet* p, TCPStream* ts);
    TCPStream* findOrCreateStream(Packet* p);
    bool isSet(uint8_t flags, uint8_t bitmask);
    bool isFresh(uint32_t seq, TCPData* ts);
    void refreshTimeout(TCPStream* ts);
    void expireList(bool all, TimeoutList& list, timeval currentTime);
    void changeList(TCPStream* ts);

    StreamHashTable::bucket_type* base_buckets;    /**< Base buckets for the hashtable */
    StreamHashTable* htable;                       /**< Hashtable of TCPStreams */

    TimeoutList openedStreams;  /**< List that stores opened TCP streams in order of their expiry */
    TimeoutList closedStreams;  /**< List that stores closed TCP streams in order of their expiry */

    uint32_t streamCounter;     /**< Internal stream counter, used to distinguish between old and re-opened TCP streams in
                                     the PacketAggregator. Otherwise it is possible that the hashtable buckets in the
                                     PacketAggregator are reused before they are exported. That would obviously cause errors. */

    uint32_t TIMEOUT_OPENED; /**< Specifies the time in ms a TCP stream may remain idle before expiring. */
    uint32_t TIMEOUT_CLOSED; /**< Specifies the time in ms that is kept after connection close before expiring. useful to filter out packets which arrive delayed. */

    uint32_t MAX_BUFFERED_BYTES; /**< The maximal number of bytes buffered per TCP connection if segments are out-of-order. */
    uint32_t MAX_BUFFERED_BYTES_HTTP; /**< The maximal number of bytes buffered per HTTP message if payload needs to be combined to be parsed successfully. */
};

#endif
