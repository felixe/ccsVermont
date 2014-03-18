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
#include <stdint.h>

/**
 * This class provides methods to parse HTTP messages and data structures which are used to
 * store relevant information about HTTP request and response messages.
 */
class HttpAggregation {
public:
	static const uint8_t MAX_STREAM_DEPTH	= 0xFF;	//TODO unused

	 //! this type represents the current state of the message parsing process
	typedef uint8_t http_status_t;

	static const http_status_t NO_MESSAGE           = 0x00; /**< http message did not start yet */
	static const http_status_t MESSAGE_REQ_METHOD   = 0x01; /**< http request method was parsed successfully */
	static const http_status_t MESSAGE_REQ_URI      = 0x03; /**< http request uri was parsed successfully */
	static const http_status_t MESSAGE_REQ_VERSION  = 0x07; /**< http request version was parsed successfully */
	static const http_status_t MESSAGE_RES_VERSION  = 0x01; /**< http response version was parsed successfully */
	static const http_status_t MESSAGE_RES_CODE     = 0x03; /**< http response status code was parsed successfully */
	static const http_status_t MESSAGE_RES_PHRASE   = 0x07; /**< http response phrase was parsed successfully */
	static const http_status_t MESSAGE_HEADER       = 0x0F; /**< http message header was parsed successfully */
	static const http_status_t MESSAGE_PROTO_UPGR   = 0x1F; /**< protocol switch was initiated after a client upgrade request */
	static const http_status_t MESSAGE_END          = 0x3F; /**< http message was parsed successfully, i.e. message end was reached */
	static const http_status_t MESSAGE_FLAG_WAITING = 0x40; /**< http message was not parsed successful, wait for more payload */
	static const http_status_t MESSAGE_FLAG_FAILURE = 0x80; /**< http message was not parsed successful, i.e. a parsing error occurred at some point */

	//! classification of the http message type
	typedef enum http_type {
		HTTP_TYPE_UNKNOWN,      /**< the type of the message is not known yet */
		HTTP_TYPE_REQUEST,      /**< the message is a http request */
		HTTP_TYPE_RESPONSE      /**< the message is a http response */
//      HTTP_TYPE_NOTIFICATION  /**< the message is a http notification */ <--- currently not used
	} http_type_t;

	//! information about the transfer of a message's entity
	typedef enum http_entity_transfer {
		// see RFC 2616 Section 4.4 for Information about Message Length
		TRANSFER_UNKNOWN,           /**< it's still unknown whether the http message has an entity */
		TRANSFER_NO_ENTITY,         /**< the message does not transport an entity */
		TRANSFER_CHUNKED,           /**< the entity is transported in chunked mode as specified by the header field 'Transfer-Encoding' */
		TRANSFER_CONTENT_LENGTH,    /**< an entity is transported and the length is specified by the header field 'Content-Length' */
		TRANSFER_CONNECTION_BASED   /**< the entity is finished when the connection closes */
	} http_entity_transfer_t;

	/**
	 * structure used for counting the number of http flows in both directions of a TCP stream
	 * these values are used by the hash functions PacketAggregator to get the proper hash-bucket related to the current flow.
	 */
	struct HttpStreamData {
		uint8_t forwardFlows;   /**< counter for the http flows in forward direction */
		uint8_t reverseFlows;   /**< counter for the http flows in reverse direction */
		uint8_t *direction;     /**< the direction of the current packet */

		bool responseFirst;     /**< indicates if the first http message observed was a response.
		                             This value should only be set to true if we are at the start of the
		                             overall Packet observation process, as it means that not all Packets
		                             were observed. Because normal HTTP dialogs always start with a request. */
		bool pipelinedRequest;  /**< indicates if the current processed packet contains multiple requests */
		bool pipelinedResponse; /**< indicates if the current processed packet contains multiple responses */

		// we assume that normally http requests should be in forward direction, because
		// the logic in the PacketHashtable puts new flows in new buckets and therefore
		// requests should always be in forward direction and as a consequence
		// responses should be in reverse direction. so the following buffers should
		// work fine, as only one response or request is sent at the same time (per stream).
		// it works also in the special case where the first message observed is a
		// response (in that case the response is in forward direction) because if the first
		// request appears new HttpStreamData is generated. so the buffers should never conflict

		// used to buffer unfinished http messages
		char *forwardLine;      /**< buffer for payload in forward direction */
		char *reverseLine;      /**< buffer for payload in reverse direction */
		uint16_t forwardLength; /**< size of the buffer buffer forward direction */
		uint16_t reverseLength; /**< size of the buffer buffer reverse direction */
	};

	struct RequestData;
	struct ResponseData;

	/**
	 * structure used for storing flow related information, which is needed for a proper aggregation
	 */
	struct FlowData {
		http_type_t forwardType; /**< http message typ in forward direction */
		http_type_t reverseType; /**< http message typ in reverse direction */

		HttpStreamData* streamInfo; /**< pointer to tcp stream related information (flowcount) */
		RequestData* request;   /**< pointer to flow related information of a http request */
		ResponseData* response; /**< pointer to flow related information of a http request */

		bool isForward();
		bool isReverse();
		bool isRequest();
		bool isResponse();
        uint8_t* getFlowcount(bool oppositeDirection = false);
        http_type_t* getType(bool oppositeDirection = false);
        http_entity_transfer_t* getTransferType();
	};

	/**
	 * structure used for storing flow related information about a request, which is needed for a proper aggregation
	 */
	struct RequestData {
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
		char *method;   /**< method of a http request */
		char *uri;      /**< uri of a http request */
		char *version;  /**< http version of a http request */

		http_status_t status;                   /**< current state in the request parsing process */
		http_entity_transfer_t entityTransfer;  /**< information about a request's entity */
		uint32_t contentLength;                 /**< stores either the remaining length of the current processed chunk or message body. max 4GB */
		uint32_t pipelinedRequestOffset;        /**< a packet can contain multiple requests. this offset indicates at which position the currently processed request starts */
		uint32_t pipelinedRequestOffsetEnd;     /**< a packet can contain multiple requests. this offset indicates at which position the currently processed request ends */
	};

	/**
	 * structure used for storing flow related information about a request, which is needed for a proper aggregation
	 */
	struct ResponseData {
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
		char *version;          /**< http version of a http request */
		char *statusCode;       /**< http version of a http request */
		char *responsePhrase;   /**< http version of a http request */

		int statusCode_;

		http_status_t status;                   /**< current state in the response parsing process */
		http_entity_transfer_t entityTransfer;  /**< information about a response's entity */
		uint32_t contentLength;                 /**< stores either the remaining length of the current processed chunk or message body. max 4GB */
        uint32_t pipelinedResponseOffset;        /**< a packet can contain multiple requests. this offset indicates at which position the currently processed request starts */
        uint32_t pipelinedResponseOffsetEnd;     /**< a packet can contain multiple requests. this offset indicates at which position the currently processed request ends */
	};

	typedef struct _value_string {
		uint16_t  value;
		const char* strptr;
	} value_string;

	static HttpStreamData* initHttpStreamData();
protected:

	static void detectHttp(const char** data, const char** dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd);
	static const char* toString(http_type_t type);
	static void initializeFlowData(FlowData* flowData, HttpStreamData* streamData);
	static void printRange(const char* data, int range);

private:
	static int processNewHttpTraffic(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd);
	static int processHttpResponse(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd);
	static int processHttpRequest(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd);
	static int getSpaceDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int getCRLFDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int getDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max = 0);
	static int eatCRLF(const char* data, const char* dataEnd, const char** end);
	static uint32_t getChunkLength(const char* data, const char* dataEnd, const char** end);
	static int getRequestOrResponse(const char* data, const char* dataEnd, const char** start, const char** end, http_type_t* type);
	static int getRequestMethod(const char* data, const char* dataEnd, const char** start, const char** end);
	static void setContentLength(const char* data, const char* dataEnd, FlowData* flowData);
	static void setTransferEncoding(const char* data, const char* dataEnd, FlowData* flowData);
	static int isRequest(const char* data, const char* dataEnd);
	static int isResponse(const char* data, const char* dataEnd);
	static int isVersion(const char* data, const char* dataEnd);
	static int isNotification(const char* data, const char* dataEnd);
	static int isMessageEntityForbidden(const int httpVersion);
	static int getRequestUri(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getRequestVersion(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getResponseVersion(const char* data, const char* dataEnd, const char** start, const char** end);
	static uint16_t getResponseCode(const char* data, const char* dataEnd, const char** start, const char** end);
	static int getResponsePhrase(const char* data, const char* dataEnd, const char** start, const char** end);
	static int processMessageHeader(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int isValidMessageHeaderTerminatorSuffix(const char* data, const char* dataEnd, const char** end);
	static int processMessageHeaderField(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static int processEntity(const char* data, const char* dataEnd, const char** end, FlowData* flowData);
	static void storeDataLeftOver(const char* data, const char* dataEnd, FlowData* flowData);
	static void copyToCharPointer(char** dst, const char* data, size_t size, bool terminator);
	static void addToCharPointer(char **dst, const char* data, size_t currentSize, size_t sizeToAdd);
	static void testFinishedMessage(FlowData* flowData);

	static const char STR_CONTENT_LENGTH[];
	static const int SIZE_CONTENT_LENGTH = 15;
	static const char STR_TRANSFER_ENCODING[];
	static const int SIZE_TRANSFER_ENCODING = 18;

	static const value_string vals_status_code[];
};

// FIXME remove me! only used for developing purposes
#define ASSERT_(exp, description)                                                                        \
    {                                                                                                   \
        if (!(exp)) {                                                                                   \
        	THROWEXCEPTION("%s\nfilename: %s:%d, function: %s (%s)", description, __FILE__, __LINE__, __func__, __PRETTY_FUNCTION__);    	\
        }                                                                                               \
    }

#endif
