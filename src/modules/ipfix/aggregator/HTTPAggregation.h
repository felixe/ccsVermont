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

#ifndef HTTPHELPER_H
#define HTTPHELPER_H

#include "modules/packet/Packet.h"
#include "common/msg.h"
#include "common/Sensor.h"
#include <stdint.h>
#include "common/ipfixlolib/ipfix.h"

/**
 * This class provides methods to parse HTTP messages and data structures which are used to
 * store relevant information about HTTP request and response messages.
 */
class HTTPAggregation : public Sensor {
public:
	static const uint16_t  MAX_STREAM_DEPTH	 = 0xFFFF;	//TODO unused
	static const uint32_t DEF_MAX_BUFFERED_BYTES = 10240; /**< Default limit of bytes which may be buffered per HTTP message is specified as 10 KiB. */

	 //! this type represents the current state of the message parsing process
	typedef uint16_t http_status_t;

	static const http_status_t NO_MESSAGE           = 0x0000; /**< HTTP message did not start yet */
	static const http_status_t MESSAGE_REQ_METHOD   = 0x0001; /**< HTTP request method was parsed successfully */
	static const http_status_t MESSAGE_REQ_URI      = 0x0003; /**< HTTP request uri was parsed successfully */
	static const http_status_t MESSAGE_REQ_VERSION  = 0x0007; /**< HTTP request version was parsed successfully */
	static const http_status_t MESSAGE_RES_VERSION  = 0x0010; /**< HTTP response version was parsed successfully */
	static const http_status_t MESSAGE_RES_CODE     = 0x0030; /**< HTTP response status code was parsed successfully */
	static const http_status_t MESSAGE_RES_PHRASE   = 0x0070; /**< HTTP response phrase was parsed successfully */
	static const http_status_t MESSAGE_HEADER       = 0x00FF; /**< HTTP message header was parsed successfully */
	static const http_status_t MESSAGE_PROTO_UPGR   = 0x01FF; /**< protocol switch was initiated after a client upgrade request */
	static const http_status_t MESSAGE_END          = 0x03FF; /**< HTTP message was parsed successfully, i.e. message end was reached */
	static const http_status_t MESSAGE_FLAG_WAITING = 0x4000; /**< HTTP message was not parsed successful, wait for more payload */
	static const http_status_t MESSAGE_FLAG_FAILURE = 0x8000; /**< HTTP message was not parsed successful, i.e. a parsing error occurred at some point */

	static const int PARSER_FAILURE = 0; /**< a failure was encountered */
	static const int PARSER_SUCCESS = 1; /**< everything went fine */
	static const int PARSER_DNF     = 2; /**< did not finish parsing, end of payload was reached prematurely */
	static const int PARSER_STOP    = 3; /**< the parsing processes stopped for some reason */

	static const int HEADER_FIELD_DNF = 0x01; /**< the end of a HTTP header field was not reached yet */
	static const int HEADER_FIELD_END = 0x02; /**< the end of a HTTP header field was reached */
	static const int HEADER_END       = 0x04; /**< HTTP message header end was reached */
	static const int HEADER_ERROR     = 0x08; /**< malformed HTTP message header */

	static const int CHUNK_START   = 0; /**< start of a new chunk is expected */
	static const int CHUNK_CRLF    = 1; /**< to complete the chunk a CRLF sequence has to be parsed */
	static const int CHUNK_ZERO    = 2; /**< a chunk size of zero has been parsed, i.e. the last chunk of a chunked HTTP message must ensue.
	                                            which in fact is a zero-length chunk. */
	static const int CHUNK_TRAILER = 3; /**< the last chunk was parsed, a trailer might follow */

	//! classification of the HTTP message type
	typedef enum http_type {
		HTTP_TYPE_UNKNOWN,      /**< the type of the message is not known yet */
		HTTP_TYPE_REQUEST,      /**< the message is a HTTP request */
		HTTP_TYPE_RESPONSE      /**< the message is a HTTP response */
//      HTTP_TYPE_NOTIFICATION  /**< the message is a HTTP notification */ <--- currently not used
	} http_type_t;

	//! information about the length of the message-body and how it is transferred
	typedef enum http_msg_body_transfer {
		// see RFC 2616 Section 4.4 for Information about Message Length
		TRANSFER_UNKNOWN,            /**< it's still unknown whether the HTTP message has a message-body */
		TRANSFER_NO_MSG_BODY,        /**< the message does not transport a message-body */
		TRANSFER_CHUNKED,            /**< the message-body is transported in chunked mode as specified by the header field 'Transfer-Encoding' */
		TRANSFER_CONTENT_LENGTH,     /**< an message-body is transported and the length is specified by the header field 'Content-Length' */
		TRANSFER_CONNECTION_BASED,   /**< the message-body is finished when the connection closes */
		TRANSFER_MULTIPART_BYTERANGE /**< the message-body is transferred as multipart/byterange Content-type */
	} http_msg_body_transfer_t;

	/**
	 * structure used for counting the number of HTTP flows in both directions of a TCP stream
	 * these values are used by the hash functions PacketAggregator to get the proper hash-bucket related to the current flow.
	 */
	struct HTTPStreamData {
		http_type_t forwardType; /**< HTTP message typ in forward direction */
		http_type_t reverseType; /**< HTTP message typ in reverse direction */

		uint16_t forwardFlows;   /**< counter for the HTTP flows in forward direction */
		uint16_t reverseFlows;   /**< counter for the HTTP flows in reverse direction */
		uint8_t *direction;     /**< the direction of the current packet */

		bool multipleRequests;  /**< indicates if the current processed packet contains multiple requests */
		bool multipleResponses; /**< indicates if the current processed packet contains multiple responses */

		// used to buffer unfinished HTTP messages
		char *forwardLine;      /**< buffer for payload in forward direction */
		char *reverseLine;      /**< buffer for payload in reverse direction */
		uint16_t forwardLength; /**< size of the buffer buffer forward direction */
		uint16_t reverseLength; /**< size of the buffer buffer reverse direction */

	    uint32_t MAX_BUFFERED_BYTES; /**< Maximal number of bytes of payload which may be buffered per HTTP message.
                                          (If the payload of a segment cannot be parsed completely we have to buffer
                                          the non-parsed part.)*/

	    uint32_t forwardLostBytes; /**< Number of lost bytes in forward direction. We update this value in the TCPMonitor if we realize, that some packets were not captured. */
	    uint32_t reverseLostBytes; /**< Number of lost bytes in reverse direction. We update this value in the TCPMonitor if we realize, that some packets were not captured. */

	};

	/**
	 * structure used for storing flow related information, which is needed for a proper aggregation
	 */
	struct FlowData {

		HTTPStreamData* streamInfo; /**< pointer to tcp stream related information (flowcount) */

		char* tempBuffer; /** used when we payload of two different TCP segments has to be combined.
		                    we cannot free it here as its content is used by PacketHashtable::aggregateHttp() */

        uint32_t* flowAnnotationFlags; /**< pointer to the annotations of the IPFIX flow */

		/**
		 * used to store flow related information about HTTP messages
		 */
		struct MessageData {
            http_status_t status;                   /**< current state in the response parsing process */
            http_msg_body_transfer_t transfer;      /**< information about a response's message-body */
            uint32_t contentLength;                 /**< stores either the remaining length of the current processed chunk or message-body. max 4GB */
            uint8_t chunkStatus;                    /**< stores status information while a chunk is parsed */
            uint32_t payloadOffset;                 /**< a packet can contain multiple HTTP messages. this offset indicates at which position the currently processed message starts */
            uint32_t payloadOffsetEnd;              /**< a packet can contain multiple HTTP messages. this offset indicates at which position the currently processed message ends */
		};

	    /**
	     * structure used for storing flow related information about a request, which is needed for a proper aggregation
	     */
	    struct RequestData : FlowData::MessageData {
	        /*-
	         * From RFC 2616
	         * Request  = Request-Line              ; Section 5.1
	         *            *(( general-header        ; Section 4.5
	         *             | request-header         ; Section 5.3
	         *             | entity-header ) CRLF)  ; Section 7.1
	         *            CRLF
	         *            [ message-body ]          ; Section 4.3
	         *
	         * Request-Line  = Method SP Request-URI SP HTTP-Version CRLF
	         */
	        char* method;   /**< method of a HTTP request */
	        char* uri;      /**< uri of a HTTP request */
	        char* version;  /**< HTTP version of a HTTP request */
	        char* host;     /**< host header field of a HTTP request */

	        uint16_t uriLength;     /**< max length of request uri */
	        uint16_t hostLength;    /**< max length of request host */
	    } request;

	    /**
	     * structure used for storing flow related information about a request, which is needed for a proper aggregation
	     */
	    struct ResponseData : FlowData::MessageData{
	        /*-
	         * From RFC 2616
	         * Response  = Status-Line               ; Section 6.1
	         *             *(( general-header        ; Section 4.5
	         *              | response-header        ; Section 6.2
	         *              | entity-header ) CRLF)  ; Section 7.1
	         *             CRLF
	         *             [ message-body ]          ; Section 7.2
	         *   Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
	         */
	        char* version;          /**< version of a HTTP request */
	        uint16_t* statusCode;   /**< status code of a HTTP request */
	        char* responsePhrase;   /**< response phrase of a HTTP request */

	        int statusCode_;        /**< stores the status code in host byte order */
	        char* boundary;         /**< stores a boundary string value. used when the message-body is transferred as Content-type: multipart/byteranges */
	        uint8_t boundaryLength; /**< stores the length of a boundary string value. used when the message-body is transferred as Content-type: multipart/byteranges */
	    } response;

		bool isForward();
		bool isReverse();
		bool isRequest();
		bool isResponse();
        uint16_t* getFlowcount(bool oppositeDirection = false);
        http_type_t* getType(bool oppositeDirection = false);
        http_msg_body_transfer_t* getTransferType();
        http_status_t* getStatus();
	};

    struct header_field_name {
        const char *name;
        const uint16_t size;
    };

    static const header_field_name FIELD_NAME_CONTENT_LENGTH;
    static const header_field_name FIELD_NAME_CONTENT_TYPE;
    static const header_field_name FIELD_NAME_ENCODING;
    static const header_field_name FIELD_NAME_HOST;

	static HTTPStreamData* initHTTPStreamData(uint32_t maxBufferedBytes = DEF_MAX_BUFFERED_BYTES);

    // statistics
    static uint64_t statTotalRequests;
    static uint64_t statTotalResponses;
    static uint64_t statTotalPartialRequests;
    static uint64_t statTotalPartialResponses;
    static uint64_t statTotalMatchedDialogPairs;
    static uint64_t statTotalBufferedBytes;
    static uint64_t statBufferedBytes;
    static uint64_t statTotalBufferOverflows;                  /**< Total number of Buffer overflows */
    static uint64_t statTotalParsingErrors;
    static uint64_t statTotalParsedHeaderBytes;

	virtual std::string getStatisticsXML(double interval);

protected:
	static void detectHTTP(const char** data, const char** dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd, const char** bodyStart);
	static const char* toString(http_type_t type);
	static void initializeFlowData(FlowData* flowData, HTTPStreamData* streamData);
	static void printRange(const char* data, int range);

private:
	static int processNewHTTPTraffic(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd, const char** bodyStart);
	static int processHTTPMessage(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd, const char** bodyStart);
	static int getSpaceDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int getCRLFDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int getDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int getDelimitedHeaderFieldValue(const char* data, const char* dataEnd, const char** start, const char** end);
	static int eatCRLF(const char* data, const char* dataEnd, const char** end);
	static int eatLineFeed(const char* data, const char* dataEnd, const char** end);
	static bool isLWSToken(const char* data);
	static bool isToken(const char* data);
	static int getChunkLength(const char* data, const char* dataEnd, const char** end, uint32_t* chunkLength);
	static int getRequestOrResponse(const char* data, const char* dataEnd, const char** start, const char** end, http_type_t* type);
	static int getRequestMethod(const char* data, const char* dataEnd, const char** start, const char** end);
	static void setContentLength(const char* data, const char* dataEnd, FlowData* flowData);
	static void setTransferEncoding(const char* data, const char* dataEnd, FlowData* flowData);
	static int isRequest(const char* data, const char* dataEnd);
	static int isResponse(const char* data, const char* dataEnd);
	static int isVersion(const char* data, const char* dataEnd);
	static int isNotification(const char* data, const char* dataEnd);
	static int isMessageBodyForbidden(const int httpVersion);
	static int getRequestUri(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getRequestVersion(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getResponseVersion(const char* data, const char* dataEnd, const char** start, const char** end);
	static uint16_t getResponseCode(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getResponsePhrase(const char* data, const char* dataEnd, const char** start, const char** end);
	static int processMessageHeader(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int isValidMessageHeaderTerminatorSuffix(const char* data, const char* dataEnd, const char** end);
	static int getHeaderField(const char* data, const char* dataEnd, const char** end);
	static int processMessageHeaderField(const char* data, const char* dataEnd, FlowData* flowData);
	static int matchFieldName(const char* data, const char* dataEnd, const char** start, const char** end, const header_field_name field);
	static int processMessageBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int processChunkedMsgBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int processFixedSizeMsgBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int processMultipartBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static void storeDataLeftOver(const char* data, const char* dataEnd, FlowData* flowData);
	static void copyToCharPointer(char** dst, const char* data, size_t size);
	static void appendToCharPointer(char **dst, const char* data, size_t currentSize, size_t sizeToAdd);
	static void addAnnotationFlag(FlowData* flowData, uint32_t annotation);
	static void testFinishedMessage(FlowData* flowData);
	static uint32_t min_(uint32_t, uint32_t);
};

#endif
