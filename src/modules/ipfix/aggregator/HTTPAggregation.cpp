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

#include "HTTPAggregation.h"
#include <sstream>

/**
 * Parses a given TCP payload and tries to detect HTTP traffic information. With the gathered knowledge it is
 * possible to match HTTP requests and responses, which are belonging to each other. All relevant information
 * is stored in the FlowData structure which is passed as an argument. After the parsing process, the start and
 * end position which should be used for aggregating the payload is stored in @p aggregationStart and @p
 * aggregationEnd. It's possible that some are bytes left over when processing the payload. This happens if the
 * parsing process cannot proceed because relevant information is missing. In that case the remaining payload
 * which could not be processed is copied into a buffer. When the next packet payload is processed this buffer
 * gets combined with the payload of the next packet. In that case the end of the payload gets stored in @p
 * dataEnd.
 * @param data Position at which the payload to be processed starts. It points to the new start afterwards, if the payload to be aggregated changes.
 * @param dataEnd Position at which the payload to be processed ends. It points to the new end afterwards, if the payload to be aggregated changes.
 * @param flowData Pointer to the FlowData structure which which is used to store and get flow related information
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start.
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 */
void HTTPAggregation::detectHTTP(const char** data, const char** dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	DPRINTFL(MSG_VDEBUG, "httpagg: START in %s direction, message type: %s",
	        flowData->isReverse() ? "reverse" : "forward", flowData->isForward() ? toString(flowData->streamInfo->forwardType) : toString(flowData->streamInfo->reverseType));
	DPRINTFL(MSG_VDEBUG, "httpagg: forwardFlows: %d, reverse Flows: %d, request status=%X, response status=%X",
	        flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows, flowData->request.status, flowData->response.status);

	*aggregationStart = *data;

//	uint32_t& lostBytes = flowData->isForward() ? flowData->streamInfo->forwardLostBytes : flowData->streamInfo->reverseLostBytes;
//
//	if (lostBytes > 0 && flowData->streamInfo->forwardType != HTTP_TYPE_UNKNOWN) {
//	    FlowData::MessageData* data = flowData->isRequest() ? static_cast<FlowData::MessageData*>(&flowData->request) : static_cast<FlowData::MessageData*>(&flowData->response);
//	    if (data->contentLength) {
//	        if (data->contentLength > lostBytes) {
//	            // we lost less then we are waiting for
//	            data->contentLength -= lostBytes;
//	            lostBytes = 0;
//	        } else {
//	            // we lost too much of the message, we can not recover
//	            // we should and our message here and start a new discovery with a new bucket
//	            lostBytes = 0;
//	            data->contentLength = 0;
//	            http_status_t* status = flowData->getStatus();
//	            *status = MESSAGE_END;
//	            *aggregationEnd = *aggregationStart;
//	            uint8_t* flowCount = flowData->getFlowcount();
//	            (*flowCount)++;
//	            return;
//	        }
//	    }
//	} else if (lostBytes > 0)
//	    lostBytes = 0; // we don't care about lost bytes on capture start

	uint32_t* payloadOffset = 0;
    if (flowData->isRequest()) payloadOffset = &flowData->request.payloadOffset;
    if (flowData->isResponse()) payloadOffset = &flowData->response.payloadOffset;

	if (payloadOffset && *payloadOffset) {
	    // we are continuing to process the payload of a packet which has been processed before.
	    // this means this packet contains multiple requests
		DPRINTFL(MSG_DEBUG, "httpagg: HTTP detection is starting with %u bytes offset", *payloadOffset);
		*aggregationStart = *data+*payloadOffset;
		*payloadOffset = 0;
	} else if (!payloadOffset || !*payloadOffset) {
		uint16_t plen = *dataEnd - *data;

		// check if the last processed packet in this direction has some left over bytes of payload which
		// have to be reconsidered in combination with the current payload
		if (flowData->isReverse() && flowData->streamInfo->reverseLength>0 && flowData->streamInfo->reverseLine) {
		    // combine the bytes left over with the current payload
			copyToCharPointer(&flowData->tempBuffer, flowData->streamInfo->reverseLine, flowData->streamInfo->reverseLength);
			appendToCharPointer(&flowData->tempBuffer, *data, flowData->streamInfo->reverseLength, plen);

			// set the pointers to the new memory area
			*data = flowData->tempBuffer;
			*aggregationStart = flowData->tempBuffer;
			*dataEnd = flowData->tempBuffer+flowData->streamInfo->reverseLength+plen;

			DPRINTFL(MSG_DEBUG, "httpagg: %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->reverseLength, *dataEnd-*data);

			// free the memory space used by the buffer
			flowData->streamInfo->reverseLength = 0;
			free(flowData->streamInfo->reverseLine);
			flowData->streamInfo->reverseLine = 0;
		} else if (flowData->isForward() && flowData->streamInfo->forwardLength>0 && flowData->streamInfo->forwardLine) {
		    // combine the bytes left over with the current payload
			copyToCharPointer(&flowData->tempBuffer, flowData->streamInfo->forwardLine, flowData->streamInfo->forwardLength);
			appendToCharPointer(&flowData->tempBuffer, *data, flowData->streamInfo->forwardLength, plen);

			// set the pointers to the new memory area
			*data = flowData->tempBuffer;
			*aggregationStart = flowData->tempBuffer;
			*dataEnd = flowData->tempBuffer+flowData->streamInfo->forwardLength+plen;

			DPRINTFL(MSG_DEBUG, "httpagg: %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->forwardLength, *dataEnd-*data);

			// free the memory space used by the buffer
			flowData->streamInfo->forwardLength = 0;
			free(flowData->streamInfo->forwardLine);
			flowData->streamInfo->forwardLine = 0;
		}
	}

	// we assume that all requests are transferred in one direction and all responses in the opposite direction.
	// hence once we know the message type for one direction, we can consider the type of the opposite direciton.
	if (!flowData->request.status && !flowData->response.status && flowData->streamInfo->forwardType == HTTP_TYPE_UNKNOWN) {
		/*
		 *  fresh start, no request or response has been detected yet. so we do not know yet in which direction
		 *  requests/responses are transferred.
		 */

		DPRINTFL(MSG_DEBUG, "httpagg: processing new traffic. trying to detect HTTP data.");

		if (!processNewHTTPTraffic(*aggregationStart, *dataEnd, flowData, aggregationStart, aggregationEnd))
		    return; // this message is not a start of a HTTP request or response

	} else {
	    // in this case we know the type of HTTP message which should be transferred in this direction

		if (flowData->request.status == MESSAGE_END && flowData->response.status == MESSAGE_END)
			THROWEXCEPTION("response and request are already finished, this flow should have been exported!");

		if (flowData->streamInfo->reverseType == flowData->streamInfo->forwardType || flowData->streamInfo->reverseType == HTTP_TYPE_UNKNOWN || flowData->streamInfo->forwardType == HTTP_TYPE_UNKNOWN)
			THROWEXCEPTION("HTTP types were set faulty, this should never happen!");

		processHTTPMessage(*aggregationStart, *dataEnd, flowData, aggregationStart, aggregationEnd);
	}

	http_status_t* status = flowData->getStatus();
	if (*status & MESSAGE_FLAG_WAITING) { // more payload required to finish processing
        // copy the bytes left over (i.e. the bytes of payload which could not be parsed) into the buffer
        storeDataLeftOver(*aggregationEnd, *dataEnd, flowData);
        *status &= ~MESSAGE_FLAG_WAITING;
	}

    if (*status & MESSAGE_FLAG_FAILURE) {
        // encountered a critical error
        msg(MSG_ERROR, "an unrecoverable failure has encountered, skipping the rest of the message.");
        *status = MESSAGE_END;
    }

    if (*status == MESSAGE_END) { // HTTP message ended
        if (flowData->isResponse()) {
            statTotalResponses++;
            if (flowData->request.status == MESSAGE_END)
                statTotalMatchedDialogPairs++;

            if (flowData->response.statusCode_ == 100) {
                DPRINTFL(MSG_VDEBUG, "httpagg: intermediate HTTP response ended");
                /*
                * HTTP responses with a status code of 100 are intermediate responses. a server for example sends
                * such a response to confirm, that a client, who requested to POST data, might deliver the message-body
                * of the POST request. after the client completes the transfer of the message-body, another response
                * is sent. thats the response we are interested in.
                *
                * From RFC 2616 Section 10.1: "A client MUST be prepared to accept one or more 1xx status responses prior
                * to a regular response, even if the client does not expect a 100 (Continue) status message."
                *
                * so we clear all the aggregation fields of the response, except for the payload, and reset the message status.
                * because we want aggregate the information of the regular response.
                */
                flowData->response.status = NO_MESSAGE;
                if (flowData->response.statusCode)
                bzero(flowData->response.statusCode, IPFIX_ELENGTH_httpResponseCode);
                if (flowData->response.version)
                bzero(flowData->response.version, IPFIX_ELENGTH_httpVersionIdentifier);
                if (flowData->response.responsePhrase)
                bzero(flowData->response.responsePhrase, IPFIX_ELENGTH_httpResponsePhrase);

                uint16_t* len = flowData->isForward() ? &flowData->streamInfo->forwardLength : &flowData->streamInfo->reverseLength;
                char* line = flowData->isForward() ? flowData->streamInfo->forwardLine : flowData->streamInfo->reverseLine;
                *len = 0;
                if (line) {
                    free(line);
                    line = 0;
                }

                flowData->response.chunkStatus = 0;
                flowData->response.contentLength = 0;
                flowData->response.transfer = TRANSFER_UNKNOWN;
            } else {
                DPRINTFL(MSG_INFO, "httpagg: HTTP response ended");
                (*flowData->getFlowcount())++;
            }
        } else if (flowData->isRequest()) {
            statTotalRequests++;
             DPRINTFL(MSG_INFO, "httpagg: HTTP request ended");

             uint8_t* requestCount = flowData->getFlowcount();
             uint8_t* responseCount = flowData->getFlowcount(true);

             if (*requestCount < *responseCount) {
                 msg(MSG_ERROR, "httpagg: request count (%d) < response count (%d). either we missed a part of the HTTP dialog or a parsing failure was encountered.", *requestCount, *responseCount);
                 *requestCount = *responseCount + 1;
                 flowData->response.status == MESSAGE_END;
             } else {
                 (*requestCount)++;
             }
         }
    }

#if 0
// XXX the following test throws an exception, if a response ends before a request. this can happen if the observer
//     misses certain parts of a HTTP dialog and we therefore are not able to match HTTP dialog pairs properly.
            testFinishedMessage(flowData);
#endif

    DPRINTFL(MSG_VDEBUG, "httpagg: forwardFlows: %d, reverse Flows: %d, request status=%X, response status=%X",
            flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows, flowData->request.status, flowData->response.status);
    DPRINTFL(MSG_VDEBUG, "httpagg: END");
}

/**
 * Checks if the payload starts with a valid HTTP method or a HTTP version code identifier.
 * On success the current flow direction can be classified as request and the other as response
 * or vice versa, depending on the identifier. Afterwards the rest of the payload is processed.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 */
int HTTPAggregation::processNewHTTPTraffic(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	http_type_t type = HTTP_TYPE_UNKNOWN;

	// check for a request or response at the beginning.
	if (getRequestOrResponse(data, dataEnd, &start, &end, &type)) {
		DPRINTFL(MSG_INFO, "httpagg: start of a new HTTP %s: '%.*s'", toString(type), end-start, start);
		if (type == HTTP_TYPE_REQUEST) {
		    statTotalPartialRequests++;
			flowData->request.status = MESSAGE_REQ_METHOD;
            if (flowData->request.method)
                memcpy(flowData->request.method, start, min_(end-start, IPFIX_ELENGTH_httpRequestMethod));

			if (flowData->isReverse()) {
				flowData->streamInfo->reverseType = HTTP_TYPE_REQUEST;
				flowData->streamInfo->forwardType = HTTP_TYPE_RESPONSE;
			} else {
				flowData->streamInfo->forwardType = HTTP_TYPE_REQUEST;
				flowData->streamInfo->reverseType = HTTP_TYPE_RESPONSE;
			}

			processHTTPMessage(end, dataEnd, flowData, aggregationStart, aggregationEnd);
		} else if (type == HTTP_TYPE_RESPONSE) {
		    statTotalPartialResponses++;
		    // the first message observed was a HTTP response, that almost never be the case.
		    // usually that means we are at the start of the Packet observation process and
		    // were not able to observe the first Packets of a TCP connection which did start
		    // before the Packet observation.
		    msg(MSG_ERROR, "httpagg: the first observed HTTP message of this TCP connection is a response...");
			flowData->response.status = MESSAGE_RES_VERSION;
            // aggregate the response version
			if (flowData->response.version)
			    memcpy(flowData->response.version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));

			if (flowData->isReverse()) {
				flowData->streamInfo->reverseType = HTTP_TYPE_RESPONSE;
				flowData->streamInfo->forwardType = HTTP_TYPE_REQUEST;
			} else {
				flowData->streamInfo->forwardType = HTTP_TYPE_RESPONSE;
				flowData->streamInfo->reverseType = HTTP_TYPE_REQUEST;
			}

			processHTTPMessage(end, dataEnd, flowData, aggregationStart, aggregationEnd);
		}

		return 1;
	}

	/*
	 * this packet seems not to be the start of a HTTP request or response, this can have several reasons, e.g.:
	 *  - this isn't a HTTP stream
	 *  - this packet is a subsequent packet of a previous unreceived HTTP request/response
	 */

	// skip package, do not aggregate payload
	DPRINTFL(MSG_DEBUG, "httpagg: no HTTP traffic in this flow direction yet!");
	*aggregationStart = dataEnd;
	*aggregationEnd = dataEnd;
	return 0;
}

/**
 * Parses a HTTP request. Tries to consume as much payload as possible. If no parsing errors occur and a remainder
 * is left over, the remaining payload is copied into a buffer for future processing. During the parsing process
 * the request status changes over the time, @see #http_status_t.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 * @return Returns 1 if the end of the message was reached, 0 otherwise
 */
int HTTPAggregation::processHTTPMessage(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;
	http_type_t type = *(flowData->getType());
	http_status_t& status = *flowData->getStatus();

	//process the request until we reach the end of the payload
	while (data<dataEnd) {
		start=end;

		switch (status) {
        case MESSAGE_PROTO_UPGR: {
            // this state can only be reached if a protocol switch (HTTP response code 101) was initiated.
            // in this case we do not process the payload, but just aggregate it
            DPRINTFL(MSG_DEBUG, "httpagg: payload continuation after protocol switch (initiated by response code 101)");
            *aggregationEnd = dataEnd;
            return 0;
        }
		case MESSAGE_END: {
			// this state should never be reached. because new TCP payload should always be put in a new flow
			msg(MSG_ERROR, "httpagg: reached invalid status, the message ended but we are still aggregating...");
#ifdef DEBUG
			THROWEXCEPTION("this point should be unreachable");
#endif
			return 1;
		}
		case NO_MESSAGE: {
		    if (type == HTTP_TYPE_REQUEST) {
                if (getRequestMethod(start, dataEnd, &start, &end)) {
                    statTotalPartialRequests++;
                    DPRINTFL(MSG_INFO, "httpagg: request method = '%.*s'", end-start, start);
                    status = MESSAGE_REQ_METHOD;
                    // aggregate the request method
                    if (flowData->request.method)
                        memcpy(flowData->request.method, start, min_(end-start, IPFIX_ELENGTH_httpRequestMethod));
                } else {
                    DPRINTFL(MSG_DEBUG, "httpagg: request method did not end yet, wait for new payload");
                    *aggregationEnd = start;
                    status = status | MESSAGE_FLAG_WAITING;
                    return 0;
                }
		    } else {
	            if (getResponseVersion(start, dataEnd, &start, &end)) {
	                statTotalPartialResponses++;
	                DPRINTFL(MSG_INFO, "httpagg: response version = '%.*s'", end-start, start);
	                status = MESSAGE_RES_VERSION;
	                // aggregate the response version
	                if (flowData->response.version)
	                    memcpy(flowData->response.version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));
	            } else {
	                if (start == dataEnd) {
	                    // skipping payload
	                    *aggregationStart = dataEnd;
	                    *aggregationEnd = dataEnd;
	                } else {
	                    DPRINTFL(MSG_DEBUG, "httpagg: response version did not end yet, wait for new payload");
	                    *aggregationEnd = start;
	                    status = status | MESSAGE_FLAG_WAITING;
	                }
	                return 0;
	            }
		    }
			break;
		}
		case MESSAGE_REQ_METHOD: {
			if (getRequestUri(start, dataEnd, &start, &end)) {
				DPRINTFL(MSG_INFO, "httpagg: request uri = '%.*s'", end-start, start);
				status = MESSAGE_REQ_URI;
	            // aggregate the request uri
				if (flowData->request.uri)
				    memcpy(flowData->request.uri, start, min_(end-start, flowData->request.uriLength));
			} else {
			    DPRINTFL(MSG_DEBUG, "httpagg: request uri did not end yet, wait for new payload");
                *aggregationEnd = start;
                status = status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;
		}
		case MESSAGE_REQ_URI: {
			if (getRequestVersion(start, dataEnd, &start, &end)) {
				status = MESSAGE_REQ_VERSION;
				DPRINTFL(MSG_INFO, "httpagg: request version = '%.*s'", end-start, start);
                // aggregate the request version
				if (flowData->request.version)
				    memcpy(flowData->request.version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));
                eatCRLF(end, dataEnd, &end);
			} else {
			    DPRINTFL(MSG_DEBUG, "httpagg: request version did not end yet, wait for new payload");
                *aggregationEnd = start;
                status = status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;
		}
		case MESSAGE_REQ_VERSION: {
			if (processMessageHeader(start, dataEnd, &end, flowData)) {
			    DPRINTFL(MSG_INFO, "httpagg: processed message-header successfully");
				if (flowData->request.transfer == TRANSFER_NO_MSG_BODY) {
					// we are finished here since the message should not contain a message-body
					status = MESSAGE_END;
					*aggregationEnd = end;
					if (end<dataEnd) {
						DPRINTFL(MSG_INFO, "httpagg: still %d bytes payload remaining, the segment may contain multiple requests", dataEnd-end);
						return 1;
					}
					return 1;
				} else {
					status = MESSAGE_HEADER;
				}
				//DPRINTFL(MSG_VDEBUG, "httpagg: message-header fields = \n'%.*s'", end-start, start);
			} else {
				DPRINTFL(MSG_DEBUG, "httpagg: request header did not end yet, wait for new payload");
				*aggregationEnd = end;
				status = status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
        case MESSAGE_RES_VERSION: {
            int code = getResponseCode(start, dataEnd, &start, &end);
            flowData->response.statusCode_ = code;
            if (code) {
                if (isMessageBodyForbidden(code))
                    flowData->response.transfer = TRANSFER_NO_MSG_BODY;
                if (code == 101) {
                    DPRINTFL(MSG_INFO, "httpagg: protocol switching status code detected");
                    // the status in both direction has to be changed to MESSAGE_PROTO_UPGR.
                    // but we still need to parse the response phrase...
                    // so for now the new state is only applied for the request.
                    flowData->request.status = MESSAGE_PROTO_UPGR;
                    uint8_t* requestCount = flowData->getFlowcount(true);
                    uint8_t* responseCount = flowData->getFlowcount();
                    // new flows MUST NOT be created from now on, therefore the request
                    // flow counter has to be decremented.
                    // on the contrary all payload MUST be aggregated into the current flow.
                    // it should be legit to do it this way, since the client has to wait for
                    // the server's response, after the upgrade request has been sent. therefore
                    // no additional messages should be sent in request direction in the meantime.
                    if (*requestCount > *responseCount)
                        (*requestCount)--;
                }
                status = MESSAGE_RES_CODE;
                DPRINTFL(MSG_INFO, "httpagg: response status code = '%.*s'", end-start, start);
                // aggregate the response code
                if (flowData->response.statusCode)
                    *flowData->response.statusCode = htons(code);
            } else {
                DPRINTFL(MSG_DEBUG, "httpagg: response code did not end yet, wait for new payload");
                *aggregationEnd = start;
                status = status | MESSAGE_FLAG_WAITING;
                return 0;
            }
            break;

        }
        case MESSAGE_RES_CODE: {
            if (getResponsePhrase(start, dataEnd, &start, &end)) {
                status = MESSAGE_RES_PHRASE;
                DPRINTFL(MSG_INFO, "httpagg: response phrase = '%.*s'", end-start, start);
                // aggregate the response phrase
                if (flowData->response.responsePhrase)
                        memcpy(flowData->response.responsePhrase, start, min_(end-start, IPFIX_ELENGTH_httpResponsePhrase));
                eatCRLF(end, dataEnd, &end);

                if (flowData->response.statusCode_ == 101) {
                    DPRINTFL(MSG_INFO, "httpagg: skipping the rest of the payload because of protocol switching");
                    // if we are switching protocol, we are done with message parsing. from now on
                    // we just have to aggregate the payload
                    status = MESSAGE_PROTO_UPGR;
                    *aggregationEnd = dataEnd;
                    return 0;
                }
            } else {
                DPRINTFL(MSG_DEBUG, "httpagg: response phrase did not end yet, wait for new payload");
                *aggregationEnd = start;
                status = status | MESSAGE_FLAG_WAITING;
                return 0;
            }
            break;
        }
        case MESSAGE_RES_PHRASE: {
            if (processMessageHeader(start, dataEnd, &end, flowData)) {
                if (flowData->response.transfer == TRANSFER_NO_MSG_BODY) {
                    // we are finished here since the message should not contain a message-body
                    status = MESSAGE_END;
                    if (end!=dataEnd) {
                        DPRINTFL(MSG_INFO, "httpagg: still %d bytes payload remaining, the segment may contain multiple responses", dataEnd-data);
                    }
                    *aggregationEnd = end;
                    return 1;
                } else {
                    status = MESSAGE_HEADER;
                }
            } else {
                DPRINTFL(MSG_DEBUG, "httpagg: response header did not end yet, wait for new payload");
                *aggregationEnd = end;
                status = status | MESSAGE_FLAG_WAITING;
                return 0;
            }
            break;
        }
		case MESSAGE_HEADER: {
		    int result = processMessageBody(start, dataEnd, &end, flowData);
		    if (result == PARSER_SUCCESS) {
				status = MESSAGE_END;
				*aggregationEnd = end;
				return 1;
			} else if (result == PARSER_DNF) {
                DPRINTFL(MSG_VDEBUG, "httpagg: %s message-body did not end yet, wait for new payload", toString(type));
                *aggregationEnd = end;
                if (*aggregationEnd < dataEnd)
                    status = status | MESSAGE_FLAG_WAITING;
                return 0;
            } else if (result == PARSER_FAILURE) {
                msg(MSG_ERROR, "httpagg: a failure was encountered while processing the HTTP message-body");
            }
			*aggregationEnd = dataEnd;
			return 0;
			break;
		}
		default:
			THROWEXCEPTION("unhandled or unknown HTTP %s status: 0x%x", toString(type), flowData->response.status);
		}
	}

	// end of the HTTP message hasn't been reached yet, aggregate the entire payload
	*aggregationEnd = dataEnd;
	return 0;
}

/**
 * Parses the message-header until we match ("\r\n" | "\n\n" | "\n\r\n") or reach the end of the packet.
 * See isValidMessageHeaderTerminatorSuffix() for the reason.
 * During the parsing process we check for the optional header fields "Transfer-Encoding" and "Content-Length", which
 * give us information about the length of the message-body which might follow the message-header
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @return returns 0 if the message-header did not end yet, 1 otherwise
 */
int HTTPAggregation::processMessageHeader(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
    if (data >= dataEnd)
        return 0;

	http_msg_body_transfer_t* transferType = flowData->getTransferType();
    *end = data;

    while(data<dataEnd) {
        const char *headFieldEnd = 0;
        const int status = getHeaderField(data, dataEnd, end);

        switch (status) {
            case (HEADER_END | HEADER_FIELD_END): {
                const char* tempEnd = 0;
                if (processMessageHeaderField(data, *end, flowData) == PARSER_FAILURE) {
                    msg(MSG_ERROR, "header field parsing error. could not parse the last header field.");
#if DEBUG
                    if (msg_getlevel()>=MSG_VDEBUG) {
                        printf("Header Field ");
                        printRange(data, *end-data);
                    }
#endif
                }
            }
            /* no break */
            case HEADER_END:
                if (*transferType == TRANSFER_UNKNOWN ) {
                    if (flowData->isRequest()) {
                        // HTTP requests which do not supply a length header field cannot transfer a message-body.
                        // From RFC 2616:
                        // "Closing the connection cannot be used to indicate the end of a request body,
                        // since that would leave no possibility for the server to send back a response."
                        *transferType = TRANSFER_NO_MSG_BODY;
                    } else {
                        // we assume the length of the message-body is determined by the server closing the connection
                        *transferType = TRANSFER_CONNECTION_BASED;
                    }
                }
                return 1;
            case HEADER_FIELD_END: {
                if (processMessageHeaderField(data, *end, flowData) == PARSER_FAILURE) {
                    msg(MSG_ERROR, "header field parsing error. could not parse header field.");
#if DEBUG
                    if (msg_getlevel()>=MSG_VDEBUG) {
                        printf("Header Field ");
                        printRange(data, *end-data);
                    }
#endif
                }
            }
                break;
            case HEADER_FIELD_DNF:
                // the header field spans over multiple TCP segments
                return 0;
            case HEADER_ERROR:
                msg(MSG_ERROR, "could not parse HTTP message-header. the header seems to be malformed.");
            default:
                THROWEXCEPTION("invalid message-header parsing status");
                break;
        }
        data = *end;
        if (data == dataEnd)
            msg(MSG_ERROR, "invalid message-header parsing status");
    }
    msg(MSG_ERROR, "invalid message-header parsing status");

	return 0;
}

/**
 * Checks for a valid CRLF sequence at the beginning
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end On success used to store the position at which the parsing process stopped
 * @return Returns 1 if the sequence is valid, else otherwise
 */
int HTTPAggregation::isValidMessageHeaderTerminatorSuffix(const char* data, const char* dataEnd, const char** end) {
	/*
	 * The four possible ways to terminate a HTTP request are:
	 * - '\r\n\r\n'
	 * - '\r\n\n'
	 * - '\n\r\n'
	 * - '\n\n'
	 *
	 * Since '\n\r\n' and '\n\n' are common suffixes to all it should
	 * also be enough only to check for them.
	 */
	*end = data;
	if (*data == '\n') {
		data++;
		if (dataEnd-data >= 2 && *data == '\r') {
			data++;
			if (*data == '\n') {
				*end=data+1;
				return 1;
			} else {
				return 0;
			}
		} else if (*data=='\n'){
			*end=data+1;
			return 1;
		}
	}
	return 0;
}

/**
 * Searches for the end of a HTTP header field.
 *
 * A HTTP header field can be folded over several lines. This function determines
 * the position at which the HTTP header field ends, if enough payload is provided.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @return #HEADER_END if the HTTP message-header end was reached
 *          #HEADER_ERROR if a parsing error encountered
 *          #HEADER_FIELD_DNF if the end of a header field was not reached yet
 *          #HEADER_FIELD_END if the end of a header field was reached
 */
int HTTPAggregation::getHeaderField(const char* data, const char* dataEnd, const char** end) {
    *end = data;

    if (eatCRLF(data, dataEnd, end) || eatLineFeed(data, dataEnd, &data)) {
        // if we start with a CRLF or line feed the end of the HTTP message-header was reached
        return HEADER_END;
    }

    if (!isToken(data)) {
        // this cannot be a valid header field since we did not start with a token
        return HEADER_ERROR;
    }

    while (data < dataEnd) {
        if (eatCRLF(data, dataEnd, &data) || eatLineFeed(data, dataEnd, &data)) {
            if (eatCRLF(data, dataEnd, &data) || eatLineFeed(data, dataEnd, &data)) {
                // we got two line breaks in a row, that means the HTTP message-header ended
                *end = data;
                return HEADER_END | HEADER_FIELD_END;
            }
            // we got a line break
            if (data == dataEnd) {
                // no characters left
                return HEADER_FIELD_DNF;
            } else {
                // there are characters left after the line break
                if (isToken(data)) {
                    // a line break followed by a token indicates that we have reached the next header field
                    *end = data;
                    return HEADER_FIELD_END;
                }
            }
        } else {
            data++;
        }
    }

    // no characters left
    return HEADER_FIELD_DNF;
}

/**
 * Checks a range of payload against HTTP header field names, which are relevant for us. If a interesting
 * field was found, the proper action is taken.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @return #PARSER_SUCCESS if the HTTP header field name did match and a HTTP header field value was found
 *         #PARSER_DNF if a part of the payload did match, but the end of the payload was reached
 *         #PARSER_FAILURE if an error was encountered
 *         #PARSER_STOP if none of the header field names, which are relevant to us, did match
 */
int HTTPAggregation::processMessageHeaderField(const char* data, const char* dataEnd, FlowData* flowData) {
    http_msg_body_transfer_t* transferType = flowData->getTransferType();

    const char* fieldValueStart = 0;
    const char* fieldValueEnd = data;

    int status = PARSER_STOP;

    // Chunked Transfer-Encoding takes precedence over Content-Length
    // ATTENTION: this construct works because all header fields, which are of interest for us, begin
    // with a distinct character
	if (*transferType != TRANSFER_CHUNKED &&
	        *transferType != TRANSFER_NO_MSG_BODY) {
	    status = matchFieldName(data, dataEnd, &fieldValueStart, &fieldValueEnd, FIELD_NAME_CONTENT_LENGTH);
	    if (status == PARSER_SUCCESS) {
	        setContentLength(fieldValueStart, fieldValueEnd, flowData);
	    }
	    if (status != PARSER_STOP) {
	        // we don't have to check for the other field names, because we had a match
	        return status;
	    }
	}
	if (*transferType != TRANSFER_NO_MSG_BODY) {
	    status = matchFieldName(data, dataEnd, &fieldValueStart, &fieldValueEnd, FIELD_NAME_ENCODING);
	    if (status == PARSER_SUCCESS) {
	        setTransferEncoding(fieldValueStart, fieldValueEnd, flowData);
	    }
        if (status != PARSER_STOP) {
            // we don't have to check for the other field names, because we had a match
            return status;
        }

	}

	if (flowData->request.host) {
	    status = matchFieldName(data, dataEnd, &fieldValueStart, &fieldValueEnd, FIELD_NAME_HOST);
	    if (status == PARSER_SUCCESS) {
            // aggregate request host header field
            memcpy(flowData->request.host, fieldValueStart, min_(fieldValueEnd-fieldValueStart, flowData->request.hostLength));
        }
        if (status != PARSER_STOP) {
            // we don't have to check for the other field names, because we had a match
            return status;
        }
    }

    if (flowData->isResponse() &&
            flowData->response.statusCode_==206 &&
            *transferType != TRANSFER_CHUNKED &&
            *transferType != TRANSFER_CONTENT_LENGTH &&
            *transferType != TRANSFER_NO_MSG_BODY) {
        status = matchFieldName(data, dataEnd, &fieldValueStart, &fieldValueEnd, FIELD_NAME_CONTENT_TYPE);
        if (status == PARSER_SUCCESS) {
            /*- From RFC 2616 Section 14.17
             *  Content-Type   = "Content-Type" ":" media-type
             *
             *  From RFC 2616 Section 3.7
             *  media-type     = type "/" subtype *( ";" parameter )
             *  type           = token subtype = token
             *
             *  Also note:
             *  "Linear white space (LWS) MUST NOT be used between the type and subtype, nor between an attribute and its value."
             *  That eases the parsing of this header field value
             *
             *  From RFC 2046
             *  boundary := 0*69<bchars> bcharsnospace
             */
            if (!strncmp("multipart/byterange", fieldValueStart, 19)) {
                data = fieldValueStart + 19;
                bool found = false;
                // minimal required length is 11 -> because we compare against the string 'boundary=<1*TOKEN>' would requires
                // for the line break after the header field.
                while (data < dataEnd-11) {
                    if (!strncmp("boundary=", data, 9)) {
                        data+=9;
                        // the boundary delimiter can be in quotes
                        if (*data == '"') {
                            data++;
                            fieldValueStart = data;
                            while (*data!='"' && data < dataEnd)
                                data++;
                            if (data==dataEnd)
                                return PARSER_FAILURE;
                            else
                                fieldValueEnd=data;
                        } else {
                            fieldValueStart = data;
                            // TODO to reconsider since different tokens are allowed
                            while (isToken(data) && data < dataEnd)
                                data++;
                            fieldValueEnd = data;
                        }
                        int len = fieldValueEnd-fieldValueStart;

                        // From RFC 2046:
                        // Boundary delimiters must not be no longer than 70 characters, not counting the two
                        // leading hyphens.
                        if (len <= 0 || len > 70)
                            return PARSER_FAILURE;

                        DPRINTFL(MSG_VDEBUG, "httpagg: read multipart/byterange header field with boundary delimiter: \"%.*s\"", len, fieldValueStart);

                        flowData->response.transfer = TRANSFER_MULTIPART_BYTERANGE;

                        // instead of storing the boundary delimiter as is, we add "--" to the begin and end.
                        // the reason behind this is that we need the the delimiter in this form afterwards.
                        flowData->response.boundaryLength = len+4;
                        flowData->response.boundary = (char*)malloc(sizeof(char)*(len+4));
                        memcpy(flowData->response.boundary, "--", 2);
                        memcpy(flowData->response.boundary + 2, fieldValueStart, len);
                        memcpy(flowData->response.boundary + 2 + len, "--", 2);

                        return PARSER_SUCCESS;
                    }
                    data++;
                }
            }
            return PARSER_STOP;
        }
        if (status != PARSER_STOP) {
            // we don't have to check for the other field names, because we had a match
            return status;
        }

    }

    return status;
}

/**
 * Matches a range of payload against a given HTTP header field name and tries to find a valid HTTP header field value.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the HTTP header field value starts
 * @param end Used to store the position at which the HTTP header field value ends
 * @param field The HTTP header field name which is check against payload
 * @return #PARSER_SUCCESS if the HTTP header field name did match and a HTTP header field value was found
 *         #PARSER_DNF if a part of the payload did match, but the end of the payload was reached
 *         #PARSER_FAILURE if an error was encountered
 *         #PARSER_STOP if the HTTP header field name did not match
 */
int HTTPAggregation::matchFieldName(const char* data, const char* dataEnd, const char** start, const char** end, const header_field_name field) {
    if (tolower(*data) != field.name[0])
        return PARSER_STOP;

    // From RFC 2616, Section 4.2: Field names are case-insensitive.

    const char* fstart = data;
    data++;
    size_t i = 1;
    while (data < dataEnd && i < field.size) {
        if (tolower(*data) == field.name[i]) {
            i++;
        } else if (!isLWSToken(data)){
            *end = data;
            return PARSER_STOP;
        } else {
            return PARSER_DNF;
        }
        data++;
    }

    if (!isLWSToken(data)) {
        while (data < dataEnd) {
            if (*data == ':') {
                data++;
                break;
            }
            data++;
        }
    } else {
        if (*data != ':') {
            return PARSER_FAILURE;
        }
        data++;
    }

    if (data < dataEnd) {
        if (getDelimitedHeaderFieldValue(data, dataEnd, start, end)) {
            return PARSER_SUCCESS;
        } else {
            return PARSER_FAILURE;
        }
    }

    return PARSER_DNF;
}

/**
 * Stores the parsed value for the 'Transfer-Encoding' header field.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 */
void HTTPAggregation::setTransferEncoding(const char* data, const char* dataEnd, FlowData* flowData) {
	if (!strncmp(data, "identity", dataEnd-data)) {
		// if transfer encoding is set to "identity" the message length is not affected by this field.
		// so we can ignore it
		return;
	}

	// if transfer encoding is not equal to "identity" the transfer-length is defined by use of the "chunked" transfer-coding

	if (flowData->isRequest()) {
		flowData->request.transfer = TRANSFER_CHUNKED;
		DPRINTFL(MSG_INFO, "httpagg: the request transfer-length is defined by use of the \"chunked\" transfer-coding");
	} else {
		flowData->response.transfer = TRANSFER_CHUNKED;
		DPRINTFL(MSG_INFO, "httpagg: the response transfer-length is defined by use of the \"chunked\" transfer-coding");
	}
}

/**
 * Stores the parsed value for the 'Content-Length' header field
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 */
void HTTPAggregation::setContentLength(const char* data, const char* dataEnd, FlowData* flowData) {
	if (flowData->isRequest()) {
		flowData->request.transfer = TRANSFER_CONTENT_LENGTH;
		flowData->request.contentLength = strtol(data, NULL, 10);
		DPRINTFL(MSG_INFO, "httpagg: set request content-length to %u", flowData->request.contentLength);
	} else {
		flowData->response.transfer = TRANSFER_CONTENT_LENGTH;
		flowData->response.contentLength = strtol(data, NULL, 10);
		DPRINTFL(MSG_INFO, "httpagg: set response content-length to %u (parsed string = %.*s)", flowData->response.contentLength, dataEnd-data, data);
	}
}


/**
 * Parses the message-body of a HTTP message. How the message is parsed depends on the transfer type:
 *  - case #TRANSFER_NO_MSG_BODY: no length header fields were specified, no message-body should exist... nothing to do
 *  - case #TRANSFER_CHUNKED: 'Transfer-Encoding' was set in the message-header. estimate the size of each chunk and skip those bytes
 *  - case #TRANSFER_CONTENT_LENGTH: 'Content-Length' was set in the message-header, a fixed value of bytes can be skipped
 *  - case #TRANSFER_CONNECTION_BASED: the message length is determined by the server closing the connection
 *  - case #TRANSFER_MULTIPART_BYTERANGE: the message length is defined by the media type multipart/byteranges
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param transferType Pointer to the message's #http_msg_body_transfer_t type
 * @return returns #PARSER_SUCCESS if the end of the message-body was reached
 *                 #PARSER_DNF if the end was not reached
 *                 #PARSER_FAILURE if the parsing failed
 */
int HTTPAggregation::processMessageBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
	http_msg_body_transfer_t *transfer = flowData->getTransferType();
	*end = data;
	if (*transfer == TRANSFER_CHUNKED) {
	    return processChunkedMsgBody(data, dataEnd, end, flowData);
	} else if (*transfer == TRANSFER_CONTENT_LENGTH) {
	    return processFixedSizeMsgBody(data, dataEnd, end, flowData);
	} else if (*transfer == TRANSFER_MULTIPART_BYTERANGE) {
	    return processFixedSizeMsgBody(data, dataEnd, end, flowData);
    } else if (*transfer == TRANSFER_CONNECTION_BASED) {
	    // we are finished when the connection closes, hence aggregate the whole payload
	    *end = dataEnd;
	    return PARSER_SUCCESS;
	} else if (*transfer == TRANSFER_NO_MSG_BODY) {
		// the HTTP message contains no entitiy
		DPRINTFL(MSG_DEBUG, "httpagg: HTTP message contains no message-body");
		return PARSER_SUCCESS;
	} else {
		ASSERT(*transfer != TRANSFER_UNKNOWN, "transfer type was not set, should never happen");
		DPRINTFL(MSG_DEBUG, "httpagg: no message-body length was specified in the header fields");
		return PARSER_FAILURE;
	}

	return PARSER_FAILURE;
}

/**
 * Parses a message-body of a HTTP message which is transferred in chunks.
 * In this case the transfer type is set as TRANSFER_CHUNKED, which means that the 'Transfer-Encoding' header field has been parsed.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param transferType Pointer to the message's #http_msg_body_transfer_t type
 * @return returns #PARSER_SUCCESS if the end of the message-body was reached
 *                 #PARSER_DNF if the end was not reached
 *                 #PARSER_FAILURE if the parsing failed
 */
int HTTPAggregation::processChunkedMsgBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
    /*-
     * From RFC 2616 Section 3.6.1:
     *
     * Chunked-Body    = *chunk
     *                   last-chunk
     *                   trailer
     *                   CRLF
     *
     * chunk           = chunk-size [ chunk-extension ] CRLF
     *                   chunk-data CRLF
     * chunk-size      = 1*HEX
     * last-chunk      = 1*("0") [ chunk-extension ] CRLF
     * chunk-extension = *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
     * chunk-ext-name  = token
     * chunk-ext-val   = token | quoted-string
     * chunk-data      = chunk-size(OCTET)
     */

    if (dataEnd-data<=0) {
        // no remaining payload, wait for new chunk
        *end = dataEnd;
        return PARSER_DNF;
    }
    uint32_t* contentLength = 0;
    uint8_t* chunkStatus = 0;
    const char* start = data;

    if (flowData->isRequest()) {
        contentLength = &flowData->request.contentLength;
        chunkStatus = &flowData->request.chunkStatus;
    }
    else {
        contentLength = &flowData->response.contentLength;
        chunkStatus = &flowData->response.chunkStatus;
    }

    while (*chunkStatus != CHUNK_TRAILER && start < dataEnd) {
        uint32_t len = dataEnd-start;
        if (*chunkStatus == CHUNK_START && *contentLength<=0) {
            int result = getChunkLength(start, dataEnd, end, contentLength);
            if (result == PARSER_FAILURE) {
                msg(MSG_ERROR, "httpagg: error parsing chunked message, chunk-size header field value was malformed");
                return PARSER_FAILURE;
            } else if (result == PARSER_DNF) {
                msg(MSG_ERROR, "httpagg: not enough payload to parse chunk-size");
                // not enough payload remaining, wait for new payload
                *end = start;
                return PARSER_DNF;
            }

            if (*contentLength == 0)
                *chunkStatus = CHUNK_ZERO;

            start = *end;
            len = dataEnd - *end;
        }

        if (*chunkStatus == CHUNK_CRLF || *chunkStatus == CHUNK_ZERO) {
            if (dataEnd-start < 2) {
                *end = start;
                return PARSER_DNF;
            }
            if (*chunkStatus == CHUNK_ZERO && isToken(start)) {
                // a trailer seems to follow as the next char is a token
                *chunkStatus = CHUNK_TRAILER;
            } else {
                if (!eatCRLF(start, dataEnd, &start)) {
                    msg(MSG_ERROR, "httpagg: chunk did not end with a CRLF");
                    return PARSER_FAILURE;
                }

                if (*chunkStatus == CHUNK_ZERO) {
                    // we are finished because the HTTP message seems to carry no trailer
                    if (start != dataEnd)
                        msg(MSG_ERROR, "httpagg: the chuncked HTTP message ended, but there is still payload remaining");
                    *end = start;
                    return PARSER_SUCCESS;
                }

                // we parsed an intermediate chunk, another chunk has to follow
                *chunkStatus = CHUNK_START;
                *end = start;
            }
        }

        if (*contentLength>0) {
            if (*contentLength <= len) {
                DPRINTFL(MSG_VDEBUG, "httpagg: chunk ended. current part range: %u to %u (%u bytes)", *end-data, (*end+*contentLength)-data, *contentLength);
                start = *end + *contentLength;
                if (dataEnd - start > 2)
                    DPRINTFL(MSG_VDEBUG, "httpagg: this payload contains multiple chunks or multiple parts of chunks.");
                *contentLength = 0;
                *chunkStatus = CHUNK_CRLF;
            } else {
                DPRINTFL(MSG_VDEBUG, "httpagg: this payload contains a part of a chunk. current part range: %u to %u (%u bytes)", *end-data, *end-data+len, len);
                *contentLength = *contentLength-len;
                start = *end + len;
                DPRINTFL(MSG_INFO, "httpagg: current remaining chunk size: %u", *contentLength);
            }
            *end = start;
        }
    }

    while (*chunkStatus == CHUNK_TRAILER && start < dataEnd) {
        if (*contentLength != 0)
            THROWEXCEPTION("remaining chunk size != 0 while parsing the trailer.");
        int result = getHeaderField(start, dataEnd, end);

        switch (result) {
            case HEADER_FIELD_DNF:
                 return PARSER_DNF;
            case (HEADER_END|HEADER_FIELD_END):
            /* no break */
            case HEADER_END:
                DPRINTFL(MSG_INFO, "httpagg: end of chunked message");
                return PARSER_SUCCESS;
            case HEADER_ERROR:
                msg(MSG_ERROR, "httpagg: error parsing trailer of chunked message");
                return PARSER_FAILURE;
            case HEADER_FIELD_END:
                start = *end;
                break;
            default:
                break;
        }
    }

    return PARSER_DNF;
}

/**
 * Parses the message-body of a HTTP message whose length has a fixed size.
 * In this case the transfer type is set as #TRANSFER_CONTENT_LENGTH, that means the length was specified by the
 * 'Content-Length' header field in the message-header.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param transferType Pointer to the message's #http_msg_body_transfer_t type
 * @return returns #PARSER_SUCCESS if the end of the message-body was reached
 *                 #PARSER_DNF if the end was not reached
 *                 #PARSER_FAILURE if the parsing failed
 */
int HTTPAggregation::processFixedSizeMsgBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
    uint32_t* contentLength = 0;
    if (flowData->isRequest()) {
        contentLength = &flowData->request.contentLength;
    } else {
        contentLength = &flowData->response.contentLength;
    }
    if (*contentLength<dataEnd-data) {
        DPRINTFL(MSG_DEBUG, "httpagg: processed the last %u bytes of the HTTP message-body. the segment may contain multiple messages, %u bytes remaining.", dataEnd-(data + *contentLength));
        if (*contentLength>0) {
            *end = data + *contentLength;
            *contentLength = 0;
        } else {
            *end = data;
        }
        return PARSER_SUCCESS;
    } else {
        *contentLength = *contentLength - (dataEnd-data);
        *end = dataEnd;
        DPRINTFL(MSG_INFO, "httpagg: processed %u bytes of the HTTP message-body, %u bytes left.", dataEnd-data, *contentLength);
        if (*contentLength<=0)
            return PARSER_SUCCESS; // we are finished
        else
            return PARSER_DNF; // still payload left
    }
}

/**
 * Parses a message-body, of a HTTP response, composed as several byteranges.
 * In this case the transfer type is set as #TRANSFER_MULTIPART_BYTERANGE, which
 * means the 'Content-type' header field indicates that the transfer-length is
 * defined by the self-delimiting media type "multipart/byteranges".
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param transferType Pointer to the message's #http_msg_body_transfer_t type
 * @return returns #PARSER_SUCCESS if the end of the message-body was reached
 *                 #PARSER_DNF if the end was not reached
 */
int HTTPAggregation::processMultipartBody(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
    /*
     * If a HTTP response's message-body is transferred as multipart/byterange
     * media type, the transported message-body consists of at least two byterange parts.
     * Since the content of the payload does not matter to us, we can
     * ignore how the message-body is composed and simply search for the
     * final boundary delimiter in the payload to determine the end of the
     * message.
     *
     * This transfer type is only valid for HTTP responses.
     */
    while (data < (dataEnd - flowData->response.boundaryLength + 2)) {
        /*-
         * From RFC 2046:
         * "The boundary delimiter MUST occur at the beginning of a line, ..."
         * so first check for a CRLF and then try to match the final delimiter.
         * the boundary delimiter is stored in the form "--delimiter--", what
         * eases the string comparison here.
         */
        if (eatCRLF(data, dataEnd, end)) {
            if (!strncmp(*end, flowData->response.boundary, flowData->response.boundaryLength)) {
                msg(MSG_ERROR, "httpagg: end of a multipart/byterange message-body");
                /*-
                 * we cut off everything what follows, because according to RFC 2046:
                 * "...implementations must ignore anything that appears before the first
                 * boundary delimiter line or after the last one."
                 * these areas are generally only used to insert notes and should therefore
                 * not be of interest for us.
                 * so we just aggregate until the end of the final boundary delimiter
                 */
                *end = *end + flowData->response.boundaryLength;
                return PARSER_SUCCESS;
            }
        }
        data++;
    }
    *end = data;
    return PARSER_DNF;
}

/**
 * Searches for text delimited by a whitespace. Initial spaces are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position of the first non whitespace character, regardless
 * if a delimited text was found. If the whole payload consists of spaces, the pointer points to
 * the end of the payload
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HTTPAggregation::getSpaceDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
    if (max == 0)
        max = dataEnd-data;
	*start = data;
	bool found = false;
	while (data<dataEnd) {
		bool isDelimiter = *data==' ';
		if (isDelimiter && found) {
			// reached end of text
			*end = data;
			return 1;
		} else if (!isDelimiter && !found) {
			*start = data;
			found = true;
		}
		data++;
		if (data - *start > max) {
		    *start = dataEnd;
		    *end = dataEnd;
		    return 0;
		}
	}
	// move the start pointer to the end if it points to a whitespace,
	// because that means the whole payload consists of whitespaces
	if (**start==' ') {
		*start=dataEnd;
	}
	*end=dataEnd;
	return 0;
}

/**
 * Searches for text delimited by a CRLF. Initial spaces are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position of the first non whitespace character, regardless
 * if a delimited text was found. If the whole payload consists of spaces, the pointer points to
 * the end of the payload
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HTTPAggregation::getCRLFDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
    if (max == 0)
        max = dataEnd-data;
    *start = data;
    bool found = false;
    while (data<dataEnd) {
        if (found && *data=='\r') {
            data++;
            if (data==dataEnd)
                break;
            if (*data=='\n') {
                *end = data-1;
                return 1;
            }
        } else if (found && *data=='\n') { // allow request lines which end with a single '\n'
            *end = data;
            return 1;
        }
        if (!found && *data!=' ') {
            *start = data;
            found = true;
        }
        data++;
        if (data - *start > max) {
            *start = dataEnd;
            *end = dataEnd;
            return 0;
        }
    }
    *end=dataEnd;
    return 0;
}

/**
 * Searches for text delimited by a whitespace, LF or CR. Initial delimiters are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HTTPAggregation::getDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
    if (max == 0)
        max = dataEnd-data;
	*start = data;
	bool found = false;
	while (data<dataEnd) {
		bool isDelimiter = *data==' ' || *data == '\n' || *data == '\r';
		if (isDelimiter && found) {
			// reached end of text
			*end = data;
			return 1;
		} else if (!isDelimiter && !found) {
			*start = data;
			found = true;
		}
		data++;
        if (data - *start > max) {
            *start = dataEnd;
            *end = dataEnd;
            return 0;
        }
	}
	// move the start pointer to the end if it points to a whitespace,
	// because that means the whole payload consists of whitespaces
	if (**start==' ') {
		*start=dataEnd;
	}
	*end=dataEnd;
	return 0;
}

/**
 * Searches for text delimited by a whitespace, comma,  LF or CR. Initial delimiters are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HTTPAggregation::getDelimitedHeaderFieldValue(const char* data, const char* dataEnd, const char** start, const char** end) {
    *start = data;
    bool found = false;
    while (data<dataEnd) {
        bool isDelimiter = *data==' ' || *data==',' || *data == '\n' || *data == '\r';
        if (isDelimiter && found) {
            // reached end of text
            *end = data;
            return 1;
        } else if (!isDelimiter && !found) {
            *start = data;
            found = true;
        }
        data++;
    }
    *end=dataEnd;
    return 0;
}

/**
 * Skips a single CR LF sequence
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @return Returns 1 if a CR LF sequence was skipped, 0 otherwise
 */
int HTTPAggregation::eatCRLF(const char* data, const char* dataEnd, const char** end) {
	*end = data;
	while (data<dataEnd) {
		if (*data=='\r') {
			data++;
			if (data==dataEnd)
			    return 0;
			if (*data=='\n') {
				data++;
				*end = data;
				return 1;
			} else
				break;
		} else
			break;
	}
	return 0;
}

/**
 * Skips a single line break
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @return Returns 1 if a line feed was skipped, 0 otherwise
 */
int HTTPAggregation::eatLineFeed(const char* data, const char* dataEnd, const char** end) {
    *end = data;
    if (*data=='\n')
    {
        data++;
        *end = data;
        return 1;
    }
    return 0;
}

/**
 * Check if a given char is a LWS token
 * @param data Pointer to the char to check
 * @return Returns true if the char is a LWS token, false otherwise
 */
bool HTTPAggregation::isLWSToken(const char* data) {
    /*-
     * From RFC 2616
     * LWS            = [CRLF] 1*( SP | HT )
     */
    switch (*data) {
        case '\r':
        case '\n':
        case '\t':
        case ' ':
            return true;
        default:
            return false;
    }
}

/**
 * Check if a given character of a header field is a token
 * @param data Pointer to the char to check
 * @return true if the character is a token, false otherwise
 */
bool HTTPAggregation::isToken(const char* data) {
    /*-
     * From RFC 2616:
     *
     * token        =  1*<any CHAR except CTLs or separators>
     *
     * separators   = "(" | ")" | "<" | ">" | "@"
     *              | "," | ";" | ":" | "\" | <">
     *              | "/" | "[" | "]" | "?" | "="
     *              | "{" | "}" | SP | HT
     *
     * CTL          = <any US-ASCII control character
     *              (octets 0 - 31) and DEL (127)>
     */

    // CTLs
    if (*data < 32 || *data == 127)
        return false;

    // separators
    switch (*data) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        return false;
    }

    return true;
}

/**
 * Tries to parse the size of a chunk.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param chunkLength Used to store the size of the chunk in bytes
 * @return Returns #PARSER_SUCCESS if a valid chunk size could be parsed
 *                 #PARSER_FAILURE if a failure was encountered
 *                 #PARSER_DNF if the end of payload has been reached
 */
int HTTPAggregation::getChunkLength(const char* data, const char* dataEnd, const char** end, uint32_t* chunkLength) {
	/*
	 * From RFC 2616, Section 3.6
	 * chunk          = chunk-size [ chunk-extension ] CRLF
	 * chunk-size     = 1*HEX
	 */
	const char* start = data;
	while (data<dataEnd) {
		if (*data == '\r') {
			if (data+1<dataEnd) {
			    if (*(data+1) != '\n') {
			        printRange(start, data+1-start);
			        *end = data+1;
			        return PARSER_FAILURE;
			    }
			    *end = data+2;
                long int length = strtol(start, NULL, 16); // works also if chunk extensions are present
                if (length < 0 || length > 0xFFFFFFFF) {
                    msg(MSG_ERROR, "httpagg: failure parsing chunk size, size = %u (parsed string = \"%.*s\")", length, data-start, start);
                    *chunkLength = 0;
                    return PARSER_FAILURE;
                } else {
                    *chunkLength = length & 0xFFFFFFFF;
                    DPRINTFL(MSG_INFO, "httpagg: start of a new chunk. chunk size = %u (parsed string = \"%.*s\")", length, data-start, start);
                    return PARSER_SUCCESS;
                }
			} else {
			    *end=dataEnd;
				return PARSER_DNF;
			}
		}
		data++;
	}
	*end=dataEnd;
	return PARSER_DNF;
}

/**
 * Parses the request method and checks if the identifier is valid
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if the identifier is valid, 0 otherwise
 */
int HTTPAggregation::getRequestMethod(const char* data, const char* dataEnd, const char** start, const char** end) {
	*start = data;
	*end = data;
	/*
	 * From RFC 2774 - An HTTP Extension Framework
	 *
	 * Support the command prefix that identifies the presence of
	 * a "mandatory" header.
	 */
	if (dataEnd-*start>2 && !strncmp(*start, "M-", 2)) {
		data += 2;
		*start = data;
		*end = data;
	}
	if (getSpaceDelimitedText(data, dataEnd, start, end)) {
		if (isRequest(*start, *end)) {
			return 1;
		}
		DPRINTFL(MSG_INFO, "httpagg: invalid HTTP method identifier : %.*s", *end-*start, *start);
	}

	return 0;
}

/**
 * Parses the request uri.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @return Returns 1 if a space delimited text could be parsed, 0 otherwise
 */
int HTTPAggregation::getRequestUri(const char* data, const char* dataEnd, const char** start, const char** end) {
	return getSpaceDelimitedText(data, dataEnd, start, end);
}

/**
 * Parses the request version and checks if the identifier is valid.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @return Returns 1 if the identifier is valid, 0 otherwise
 */
int HTTPAggregation::getRequestVersion(const char* data, const char* dataEnd, const char** start, const char** end) {
	if (getCRLFDelimitedText(data, dataEnd, start, end, 8)) {
		if (isVersion(*start, *end)) {
			return 1;
		}
		DPRINTFL(MSG_INFO, "httpagg: invalid HTTP version specifier : '%.*s'", *end-*start, *start);
	}
	return 0;
}

/**
 * Parses the response version and checks if the identifier is valid.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @return Returns 1 if the identifier is valid, 0 otherwise
 */
int HTTPAggregation::getResponseVersion(const char* data, const char* dataEnd, const char** start, const char** end) {
	*start = data;
	*end = data;
	/*
	 * From RFC 2774 - An HTTP Extension Framework
	 *
	 * Support the command prefix that identifies the presence of
	 * a "mandatory" header.
	 */
	if (dataEnd-*start>2 && !strncmp(*start, "M-", 2)) {
		data += 2;
		*start = data;
		*end = data;
	}
	if (getSpaceDelimitedText(data, dataEnd, start, end, 8)) {
		if (isResponse(*start, *end)) {
			return 1;
		}
		DPRINTFL(MSG_INFO, "httpagg: invalid HTTP version specifier : %.*s", *end-*start, *start);
		*start = dataEnd;
	}
	// nothing did match
	*end = dataEnd;
	return 0;
}

/**
 * Parses the response code version and tries to convert the string to the corresponding int value
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @return Returns the response code if the string is valid, 0 otherwise
 */
uint16_t HTTPAggregation::getResponseCode(const char* data, const char* dataEnd, const char** start, const char** end) {
	if (getSpaceDelimitedText(data, dataEnd, start, end, 3)) {
		if (*end-*start!=3)
			return 0;
		uint16_t code = strtol(*start, NULL, 10); // we now that our text is delimited by some space
		if (code>=100 && code <= 600)
			return code;
		else return 1;
	}
	return 0;
}

/**
 * Parses the response phrase and checks if the identifier is valid
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @return Returns 1 if the identifier is valid, 0 otherwise
 */
int HTTPAggregation::getResponsePhrase(const char* data, const char* dataEnd, const char** start, const char** end) {
    return getCRLFDelimitedText(data, dataEnd, start, end);
}

/**
 * Checks if the passed payload starts with a request method or HTTP version identifier.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @param type
 * @return Returns 1 if the passed payload starts with a request method or HTTP version identifier, 0 otherwise
 */
int HTTPAggregation::getRequestOrResponse(const char* data, const char* dataEnd, const char** start, const char** end, http_type_t* type)  {
	*type = HTTP_TYPE_UNKNOWN;
	*start = data;
	*end = data;

	if (getSpaceDelimitedText(data, dataEnd, start, end, 18)) {
		/*
		 * From RFC 2774 - An HTTP Extension Framework
		 *
		 * Support the command prefix that identifies the presence of
		 * a "mandatory" header.
		 */
		if (*end-*start>2 && !strncmp(*start, "M-", 2)) {
			data += 2;
			*start = data;
			*end = data;
		}

		if (isResponse(*start, *end)) {
			*type = HTTP_TYPE_RESPONSE;
			return 1;
		} else if (isRequest(*start, *end)) {
			*type = HTTP_TYPE_REQUEST;
			return 1;
		}
	}

	// if nothing did match this payload is invalid!
	// skip this packet and do nothing with the payload.
	*start = dataEnd;
	*end = dataEnd;
	return 0;
}

// HTTP Method Identifiers were taken from Wireshark source code (see www.wireshark.org)
/**
 * Checks if the passed char range is a valid HTTP request method
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @return Returns 1 if the range contains a valid method identifier
 */
int HTTPAggregation::isRequest(const char* data, const char* dataEnd) {
	const int mlen = dataEnd-data;
	/* Check the methods that have same length */
	switch (mlen) {
	case 3:
		if (!strncmp(data, "GET", mlen) ||
			!strncmp(data, "PUT", mlen)) {
			return 1;
		}
		break;

	case 4:
		if (!strncmp(data, "COPY", mlen) ||
			!strncmp(data, "HEAD", mlen) ||
			!strncmp(data, "LOCK", mlen) ||
			!strncmp(data, "MOVE", mlen) ||
			!strncmp(data, "POLL", mlen) ||
			!strncmp(data, "POST", mlen)) {
			return 1;
		}
		break;

	case 5:
		if (!strncmp(data, "BCOPY", mlen) ||
			!strncmp(data, "BMOVE", mlen) ||
			!strncmp(data, "MKCOL", mlen) ||
			!strncmp(data, "TRACE", mlen) ||
			!strncmp(data, "LABEL", mlen) ||  /* RFC 3253 8.2 */
			!strncmp(data, "MERGE", mlen)) {  /* RFC 3253 11.2 */
			return 1;
		}
		break;

	case 6:
		if (!strncmp(data, "DELETE", mlen) ||
			!strncmp(data, "SEARCH", mlen) ||
			!strncmp(data, "UNLOCK", mlen) ||
			!strncmp(data, "REPORT", mlen) ||  /* RFC 3253 3.6 */
			!strncmp(data, "UPDATE", mlen)) {  /* RFC 3253 7.1 */
			return 1;
		}
		break;

	case 7:
		if (!strncmp(data, "BDELETE", mlen) ||
			!strncmp(data, "CONNECT", mlen) ||
			!strncmp(data, "OPTIONS", mlen) ||
			!strncmp(data, "CHECKIN", mlen)) {  /* RFC 3253 4.4, 9.4 */
			return 1;
		}
		break;

	case 8:
		if (!strncmp(data, "PROPFIND", mlen) ||
			!strncmp(data, "CHECKOUT", mlen) || /* RFC 3253 4.3, 9.3 */
			!strncmp(data, "CCM_POST", mlen)) {
			return 1;
		}
		break;

	case 9:
		if (!strncmp(data, "PROPPATCH", mlen) ||
			!strncmp(data, "BPROPFIND", mlen)) {
			return 1;
		}
		break;

	case 10:
		if (!strncmp(data, "BPROPPATCH", mlen) ||
			!strncmp(data, "UNCHECKOUT", mlen) ||  /* RFC 3253 4.5 */
			!strncmp(data, "MKACTIVITY", mlen)) {  /* RFC 3253 13.5 */
			return 1;
		}
		break;

	case 11:
		if (!strncmp(data, "MKWORKSPACE", mlen) || /* RFC 3253 6.3 */
			!strncmp(data, "RPC_CONNECT", mlen) || /* [MS-RPCH] 2.1.1.1.1 */
			!strncmp(data, "RPC_IN_DATA", mlen)) { /* [MS-RPCH] 2.1.2.1.1 */
			return 1;
		}
		break;

	case 12:
		if (!strncmp(data, "RPC_OUT_DATA", mlen)) { /* [MS-RPCH] 2.1.2.1.2 */
			return 1;
		}
		break;

	case 15:
		if (!strncmp(data, "VERSION-CONTROL", mlen)) {  /* RFC 3253 3.5 */
			return 1;
		}
		break;

	case 16:
		if (!strncmp(data, "BASELINE-CONTROL", mlen)) {  /* RFC 3253 12.6 */
			return 1;
		}
		break;
	default:
		break;
	}
	return 0;
}

/**
 * Checks if the passed char range is a valid HTTP response identifier
 * This does not handle HTTP 0.9 replies
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @return Returns 1 if the range contains a valid response identifier
 */
int HTTPAggregation::isResponse(const char* data, const char* dataEnd) {
	const int mlen = dataEnd-data;
	/* Check the methods that have same length */
	switch (mlen) {

	// ICY isn't relevant currently
//	case 3:
//		if (!strncmp(data, "ICY", mlen)) {
//			return 1;
//		}
//		break;

	case 8:
		return isVersion(data, dataEnd);
		break;

	default:
		break;
	}
	return 0;
}

/**
 * Checks if the passed char range is a valid HTTP response version identifier
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @return Returns 1 if the range contains a valid response version identifier
 */
int HTTPAggregation::isVersion(const char* dataPtr, const char* dataEnd) {
	const int mlen = dataEnd-dataPtr;

	if (mlen != 8) {
		return 0;
	}

	if (!strncmp(dataPtr, "HTTP/", 4)) {
		return 1;
	}

	return 0;
}

/**
 * Checks if the passed char range is a valid HTTP notification identifier
 * Currently HTTP notifications are unsupported, but may be used in future releases.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @return Returns 1 if the range contains a valid notification identifier
 */
int HTTPAggregation::isNotification(const char* data, const char* dataEnd) {
	const int mlen = dataEnd-data;
	/* Check the methods that have same length */
	switch (mlen) {

	case 6:
		if (!strncmp(data, "NOTIFY", mlen)) {
			return 1;
		}
		break;

	case 9:
		if (!strncmp(data, "SUBSCRIBE", 4)) {
			return 1;
		}
		break;
	case 11:
		if (!strncmp(data, "UNSUBSCRIBE", 4)) {
			return 1;
		}
		break;

	default:
		break;
	}
	return 0;
}

/**
 * Checks if the given status code forbids the use of a message-body
 * @param statusCode Code to check
 * @return Returns 1 if a message-body is forbidden for this code, 0 otherwise
 */
int HTTPAggregation::isMessageBodyForbidden(const int statusCode) {
	/*
	 * certain response codes forbid a message-body
	 *
	 * From RFC 2616 Section 4.4
	 * Any response message which "MUST NOT" include a message-body (such as the 1xx, 204,
	 * and 304 responses and any response to a HEAD request) is always terminated by the
	 * first empty line after the header fields, regardless of the entity-header fields
	 * present in the message.
	 *
	 * Status code 101, which indicates a protocol switch, is handled separately.
	 */
	if ((statusCode == 100) ||
			statusCode == 204 ||
			statusCode == 304) {
		return 1;
	}
	return 0;
}


/**
 * Copies 'size' bytes of 'src' to the end of '*dst' and adds the null terminator
 * @param dst Destination
 * @param src Source
 * @param size Number of bytes to copy
 */
void HTTPAggregation::copyToCharPointer(char** dst, const char* src, size_t size) {
	*dst = (char*)malloc(sizeof(char)*(size));
	memcpy(*dst, src, size);
}

/**
 * Appends 'size' bytes of 'src' to the end of '*dst'
 * @param dst Destination
 * @param src Source
 * @param dstLenth Current size of the destination buffer
 * @param size Number of bytes to add
 */
void HTTPAggregation::appendToCharPointer(char **dst, const char* src, size_t dstLenth, size_t size) {
	*dst = (char*)realloc(*dst, dstLenth+size);
	memcpy(*dst+dstLenth, src, size);
}

/**
 * Stores the given payload in the proper buffer. When the next packet arrives the content
 * of the buffer will be combined with the payload of the new packet.
 * @param data Pointer to the payload to be stored
 * @param dataEnd Pointer to the end of the payload to be stored
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param reverseDirection Whether the current flow is in reverse direction or not
 */
void HTTPAggregation::storeDataLeftOver(const char* data, const char* dataEnd, FlowData* flowData) {
    // not enough characters remaining to proceed processing now.
    // put remaining characters in the buffer and wait for new data to arrive.
    uint16_t size = dataEnd-data;
    if (size > 0) {
        uint16_t &length = flowData->isForward() ? flowData->streamInfo->forwardLength : flowData->streamInfo->reverseLength;
        if (length + size > flowData->streamInfo->MAX_BUFFERED_BYTES) {
            msg(MSG_ERROR, "httpagg: reached the max number of bytes allowed to be buffered for a HTTP message.");
            http_status_t* status = flowData->getStatus();
            *status |= MESSAGE_FLAG_FAILURE;
            return;
        }

        statBufferedBytes += size;
        statTotalBufferedBytes += size;

        char **dst = flowData->isReverse() ? &flowData->streamInfo->reverseLine : &flowData->streamInfo->forwardLine;

        copyToCharPointer(dst, data, size);
        if (flowData->isReverse()) flowData->streamInfo->reverseLength = size;
        else flowData->streamInfo->forwardLength = size;
        DPRINTFL(MSG_DEBUG, "httpagg: copying %u bytes of left over payload to buffer.", size);
        DPRINTFL(MSG_VDEBUG, "httpagg: storing message : %.*s", size, data);
    } else {
        DPRINTFL(MSG_VDEBUG, "httpagg: no payload has to be stored in the buffer");
    }
}

/**
 * Initializes the given FlowData structure
 */
void HTTPAggregation::initializeFlowData(FlowData* flowData, HTTPStreamData* streamData) {
	flowData->streamInfo = streamData;
	flowData->tempBuffer = 0;

	flowData->request.method = 0;
	flowData->request.uri = 0;
	flowData->request.version = 0;
	flowData->request.host = 0;
	flowData->request.hostLength = 0;
	flowData->request.uriLength = 0;
	flowData->request.status = NO_MESSAGE;
	flowData->request.transfer = TRANSFER_UNKNOWN;
	flowData->request.contentLength = 0;
	flowData->request.payloadOffset = 0;
	flowData->request.payloadOffsetEnd = 0;

	flowData->response.version = 0;
	flowData->response.statusCode = 0;
	flowData->response.responsePhrase = 0;
	flowData->response.status = NO_MESSAGE;
	flowData->response.transfer = TRANSFER_UNKNOWN;
	flowData->response.contentLength = 0;
    flowData->response.payloadOffsetEnd = 0;
    flowData->response.payloadOffsetEnd = 0;
    flowData->response.statusCode_ = 0;
    flowData->response.chunkStatus = 0;
}

/**
 * Initializes a new HttpStreamData structure
 */
HTTPAggregation::HTTPStreamData* HTTPAggregation::initHTTPStreamData(uint32_t maxBufferedBytes) {
    HTTPStreamData* httpData = new HTTPStreamData;
	httpData->forwardFlows = 0;
	httpData->reverseFlows = 0;
	httpData->direction = 0;
	httpData->forwardType = HTTP_TYPE_UNKNOWN;
	httpData->reverseType = HTTP_TYPE_UNKNOWN;

	httpData->multipleRequests = false;
	httpData->multipleResponses = false;

	httpData->forwardLine = 0;
	httpData->reverseLine = 0;
	httpData->forwardLength = 0;
	httpData->reverseLength = 0;

	httpData->MAX_BUFFERED_BYTES = maxBufferedBytes;

	return httpData;
}

/**
 * Convenience function
 * @return true if the current payload is transferred in forward direction, false otherwise
 */
bool HTTPAggregation::FlowData::isForward() {
    return *streamInfo->direction == 0;
}

/**
 * Convenience function
 * @return true if the current payload is transferred in reverse direction, false otherwise
 */
bool HTTPAggregation::FlowData::isReverse() {
    return *streamInfo->direction == 1;
}

/**
 * Convenience function
 * @return true if the current type is known to be a request, false otherwise
 */
bool HTTPAggregation::FlowData::isRequest() {
    return *getType() == HTTP_TYPE_REQUEST;
}

/**
 * Convenience function
 * @return true if the current type is known to be a response, false otherwise
 */
bool HTTPAggregation::FlowData::isResponse() {
    return *getType() == HTTP_TYPE_RESPONSE;
}

/**
 * Get the @c http_type_t in the specified direction. Throws if the TCP stream direction was set incorrect.
 * @param oppositeDirection Specifies the direction. False for the current direction, true for the opposite direction. Default is false.
 * @return the type of
 */
HTTPAggregation::http_type_t* HTTPAggregation::FlowData::getType(bool oppositeDirection) {
    if (*streamInfo->direction == 0) {
        if (oppositeDirection)
            return &streamInfo->reverseType;
        else
            return &streamInfo->forwardType;
    }
    else if (*streamInfo->direction == 1) {
        if (oppositeDirection)
            return &streamInfo->forwardType;
        else
            return &streamInfo->reverseType;
    }
    THROWEXCEPTION("TCP stream direction was set incorrect");
    return NULL;
}

/**
 * Get the flow count in the specified direction. Throws if the HTTP type was set incorrect.
 * @param oppositeDirection Specifies the direction. False for the current direction, true for the opposite direction. Default is false.
 * @return a pointer to the flow counter in the specified direction
 */
uint8_t* HTTPAggregation::FlowData::getFlowcount(bool oppositeDirection) {
    http_type_t type =*getType(oppositeDirection);
    if (type == streamInfo->forwardType) {
        return &(streamInfo->forwardFlows);
    } else if (type == streamInfo->reverseType) {
        return &(streamInfo->reverseFlows);
    }
    THROWEXCEPTION("HTTP type was set incorrect");
    return NULL;
}

/**
 * Get the @c http_msg_body_transfer_t in the specified direction. Throws if the HTTP type was set incorrect.
 * @return a pointer to the http_msg_body_transfer_t in the specified direction
 */
HTTPAggregation::http_msg_body_transfer_t* HTTPAggregation::FlowData::getTransferType() {
    if (isRequest())
        return &request.transfer;
    else if (isResponse())
        return &response.transfer;
    THROWEXCEPTION("HTTP type was set incorrect");
    return NULL;
}

/**
 * Get the @c http_status_t in the specified direction. Throws if the HTTP type was set incorrect.
 * @return a pointer to the http_msg_body_transfer_t in the specified direction
 */
HTTPAggregation::http_status_t* HTTPAggregation::FlowData::getStatus() {
    if (isRequest())
        return &request.status;
    else if (isResponse())
        return &response.status;
    THROWEXCEPTION("HTTP type was set incorrect");
    return NULL;
}

/**
 * a string representation of the given HTTP type
 * @param type type to represent
 * @return string representation of passed type
 */
const char* HTTPAggregation::toString(http_type_t type) {
	switch (type) {
	case HTTP_TYPE_REQUEST: return "REQUEST";
	case HTTP_TYPE_RESPONSE: return "RESPONSE";
//	case HTTP_TYPE_NOTIFICATION: return "NOTIFICATION";
	case HTTP_TYPE_UNKNOWN:
	default:
		return "UNKNOWN";
	}
}

/**
 * Prints a given range of characters. Non printable characters are shown as dots.
 * @param data pointer to the start of the string
 * @param range number of characters to print
 */
void HTTPAggregation::printRange(const char* data, int range) {
	printf("string: '");
	for (int i=0;i<range;i++){
		if (isprint(data[i]))
			printf("%c", data[i]);
		else if (data[i] == '\n')
			printf("\\n");
		else if (data[i] == '\r')
			printf("\\r");
		else
			printf(".");
	}
	printf("'\n");
}

/**
 * Convenience function, compares to uint32_t numbers
 * @param a
 * @param b
 * @return
 */
uint32_t HTTPAggregation::min_(uint32_t a, uint32_t b) {
    if (a < b)
        return a;
    else
        return b;
}

const HTTPAggregation::header_field_name HTTPAggregation::FIELD_NAME_CONTENT_TYPE = {"content-type", 12};
const HTTPAggregation::header_field_name HTTPAggregation::FIELD_NAME_CONTENT_LENGTH = {"content-length", 14};
const HTTPAggregation::header_field_name HTTPAggregation::FIELD_NAME_ENCODING = {"transfer-encoding", 17};
const HTTPAggregation::header_field_name HTTPAggregation::FIELD_NAME_HOST = {"host", 4};

void HTTPAggregation::testFinishedMessage(FlowData* flowData) {
	http_type_t type = *flowData->getType();
	ASSERT(type != HTTP_TYPE_UNKNOWN, "HTTP type unknown");
	ASSERT(flowData->streamInfo->reverseType!=flowData->streamInfo->forwardType, "equal HTTP types");

	if (type == HTTP_TYPE_REQUEST) {
		ASSERT(flowData->request.status == MESSAGE_END, "message did not end");
		ASSERT(!(flowData->request.status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT(flowData->request.transfer != TRANSFER_UNKNOWN, "transfer type unknown");
		ASSERT(flowData->response.status != MESSAGE_END, "response must not end before request");
	} else {
		ASSERT(flowData->response.status == MESSAGE_END, "message did not end");
		ASSERT(!(flowData->response.status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT(flowData->response.transfer != TRANSFER_UNKNOWN, "transfer type unknown");
	}
}

// statistics
uint64_t HTTPAggregation::statTotalRequests;
uint64_t HTTPAggregation::statTotalResponses;
uint64_t HTTPAggregation::statTotalPartialRequests;
uint64_t HTTPAggregation::statTotalPartialResponses;
uint64_t HTTPAggregation::statTotalMatchedDialogPairs;
uint64_t HTTPAggregation::statTotalBufferedBytes;
uint64_t HTTPAggregation::statBufferedBytes;

std::string HTTPAggregation::getStatisticsXML(double interval)
{
    ostringstream oss;
    oss << "<TotalRequests>" << statTotalRequests << "</TotalRequests>";
    oss << "<TotalResponses>" << statTotalResponses << "</TotalResponses>";
    oss << "<TotalPartialRequests>" << statTotalPartialRequests << "</TotalPartialRequests>";
    oss << "<TotalPartialResponses>" << statTotalPartialResponses << "</TotalPartialResponses>";
    oss << "<TotalMatchedDialogPairs>" << statTotalMatchedDialogPairs << "</TotalMatchedDialogPairs>";
    oss << "<TotalBufferedBytes>" << statTotalBufferedBytes << "</TotalBufferedBytes>";
    oss << "<BufferedBytes>" << statBufferedBytes << "</BufferedBytes>";

    statBufferedBytes = 0;

    return oss.str();
}
