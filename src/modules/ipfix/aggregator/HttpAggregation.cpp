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

#include "HttpAggregation.h"

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
void HttpAggregation::detectHttp(const char** data, const char** dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	DPRINTFL(MSG_VDEBUG, "httpagg: START in %s direction, message type: %s",
	        flowData->isReverse() ? "reverse" : "forward", flowData->isForward() ? toString(flowData->forwardType) : toString(flowData->reverseType));
	DPRINTFL(MSG_VDEBUG, "httpagg: forwardFlows: %d, reverse Flows: %d, request status=%X, response status=%X",
	        flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows, flowData->request->status, flowData->response->status);

	*aggregationStart = *data;

	uint32_t* pipelinedOffset = 0;
    if (flowData->isRequest()) pipelinedOffset = &flowData->request->pipelinedRequestOffset;
    if (flowData->isResponse()) pipelinedOffset = &flowData->response->pipelinedResponseOffset;

	if (pipelinedOffset && *pipelinedOffset) {
	    // we are continuing to process a packets payload which has been processed before.
	    // this means this packet contains multiple requests
		DPRINTFL(MSG_DEBUG, "httpagg: http detection is starting with %u bytes offset", *pipelinedOffset);
		*aggregationStart = *data+*pipelinedOffset;
		*pipelinedOffset = 0;
	} else if (!pipelinedOffset || !*pipelinedOffset) {
		uint16_t plen = *dataEnd - *data;

		// check if the last processed packet in this direction has some left over bytes of payload which
		// have to be reconsidered in combination with the current payload
		if (flowData->isReverse() && flowData->streamInfo->reverseLength>0 && flowData->streamInfo->reverseLine) {
		    // combine the bytes left over with the current payload
			char *combined = 0;
			copyToCharPointer(&combined, flowData->streamInfo->reverseLine, flowData->streamInfo->reverseLength);
			addToCharPointer(&combined, *data, flowData->streamInfo->reverseLength, plen);

			// set the pointers to the new memory area
			*data = combined;
			*aggregationStart = combined;
			*dataEnd = combined+flowData->streamInfo->reverseLength+plen;

			DPRINTFL(MSG_DEBUG, "httpagg: %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->reverseLength, *dataEnd-*data);

			flowData->streamInfo->reverseLength = 0;
			free(flowData->streamInfo->reverseLine);
			flowData->streamInfo->reverseLine = 0;
		} else if (flowData->isForward() && flowData->streamInfo->forwardLength>0 && flowData->streamInfo->forwardLine) {
		    // combine the bytes left over with the current payload
			char* combined;
			copyToCharPointer(&combined, flowData->streamInfo->forwardLine, flowData->streamInfo->forwardLength);
			addToCharPointer(&combined, *data, flowData->streamInfo->forwardLength, plen);

			// set the pointers to the new memory area
			*data = combined;
			*aggregationStart = combined;
			*dataEnd = combined+flowData->streamInfo->forwardLength+plen;

			DPRINTFL(MSG_DEBUG, "httpagg: %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->forwardLength, *dataEnd-*data);

			flowData->streamInfo->forwardLength = 0;
			free(flowData->streamInfo->forwardLine);
			flowData->streamInfo->forwardLine = 0;
		}
	}

	if (!flowData->request->status && !flowData->response->status && flowData->forwardType == HTTP_TYPE_UNKNOWN) {
		/*
		 *  fresh start, no request or response has been detected yet.
		 *  if we start with a http request it should be possible to detect pipelined requests,
		 *  provided this is the first transmitted request.
		 */

		DPRINTFL(MSG_DEBUG, "httpagg: processing new traffic. trying to detect http data.");

		if (!processNewHttpTraffic(*aggregationStart, *dataEnd, flowData, aggregationStart, aggregationEnd))
		    return; // this message is not a start of a http request or response

	} else {
		if (flowData->request->status == MESSAGE_END && flowData->response->status == MESSAGE_END)
			THROWEXCEPTION("response and request are already finished, this flow should have been exported!");

		if (flowData->reverseType == flowData->forwardType || flowData->reverseType == HTTP_TYPE_UNKNOWN || flowData->forwardType == HTTP_TYPE_UNKNOWN)
			THROWEXCEPTION("http types were set faulty, this should never happen!");

		if (flowData->isResponse()) {
		    if (processHttpResponse(*aggregationStart, *dataEnd, flowData, aggregationStart, aggregationEnd) && flowData->streamInfo->responseFirst) {

                uint8_t* requestCount = flowData->getFlowcount(true);
                uint8_t* responseCount = flowData->getFlowcount();
                // since we started with a response the next request should be put into a new flow
                flowData->request->status = MESSAGE_END;
                if (*requestCount <= *responseCount) {
                    *requestCount = *responseCount + 1;
                }
			}
		}
		else if (flowData->isRequest())
			processHttpRequest(*aggregationStart, *dataEnd, flowData, aggregationStart, aggregationEnd);
	}

    if (flowData->isResponse()) {
        if (flowData->response->status & MESSAGE_FLAG_WAITING) { // more payload required to finish processing
            // copy the bytes left over (i.e. the bytes of payload which could not be parsed) into the buffer
            storeDataLeftOver(*aggregationEnd, *dataEnd, flowData);
            flowData->response->status &= ~MESSAGE_FLAG_WAITING;
        } else if (flowData->response->status == MESSAGE_END) { // response message ended
            if (flowData->response->statusCode_ == 100) {
                DPRINTFL(MSG_VDEBUG, "httpagg: intermediate http response ended");
                flowData->response->status = NO_MESSAGE;
                if (flowData->response->statusCode)
                    bzero(flowData->response->statusCode, IPFIX_ELENGTH_httpResponseCode);
                if (flowData->response->version)
                    bzero(flowData->response->version, IPFIX_ELENGTH_httpVersionIdentifier);
                if (flowData->response->responsePhrase)
                    bzero(flowData->response->responsePhrase, IPFIX_ELENGTH_httpResponsePhrase);

                uint16_t* len = flowData->isForward() ? &flowData->streamInfo->forwardLength : &flowData->streamInfo->reverseLength;
                char* line = flowData->isForward() ? flowData->streamInfo->forwardLine : flowData->streamInfo->reverseLine;
                *len = 0;
                if (line) {
                    free(line);
                    line = 0;
                }

                flowData->response->contentLength = 0;
                flowData->response->entityTransfer = TRANSFER_UNKNOWN;
            } else {
                DPRINTFL(MSG_INFO, "httpagg: http response ended");
#if 0
                testFinishedMessage(flowData);
#endif
                (*flowData->getFlowcount())++;
            }
        }
    } else if (flowData->isRequest()) {
        if (flowData->request->status & MESSAGE_REQ_METHOD) {
            flowData->streamInfo->responseFirst = false;
        }
        if (flowData->request->status & MESSAGE_FLAG_WAITING) { // more payload required to finish processing
            // copy the bytes left over (i.e. the bytes of payload which could not be parsed) into the buffer
            storeDataLeftOver(*aggregationEnd, *dataEnd, flowData);
            flowData->request->status &= ~MESSAGE_FLAG_WAITING;
        } else if (flowData->request->status == MESSAGE_END) { // request message ended
            DPRINTFL(MSG_INFO, "httpagg: http request ended");
#if 0
                testFinishedMessage(flowData);
#endif
            (*flowData->getFlowcount())++;
        }
    }

    DPRINTFL(MSG_VDEBUG, "httpagg: forwardFlows: %d, reverse Flows: %d, request status=%X, response status=%X",
            flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows, flowData->request->status, flowData->response->status);
    DPRINTFL(MSG_VDEBUG, "httpagg: END");
}

/**
 * Checks if the payload starts with a valid http method or a http version code identifier.
 * On success the current flow direction can be classified as request and the other as response
 * or vice versa, depending on the identifier. Afterwards the rest of the payload is processed.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 */
int HttpAggregation::processNewHttpTraffic(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	http_type_t type = HTTP_TYPE_UNKNOWN;

	// check for a request or response at the beginning.
	if (getRequestOrResponse(data, dataEnd, &start, &end, &type)) {
		DPRINTFL(MSG_INFO, "httpagg: start of a new http %s: '%.*s'", toString(type), end-start, start);
		if (type == HTTP_TYPE_REQUEST) {
		    flowData->streamInfo->responseFirst = false;
			flowData->request->status = MESSAGE_REQ_METHOD;
            if (flowData->request->method)
                memcpy(flowData->request->method, start, min_(end-start, IPFIX_ELENGTH_httpRequestMethod));

			if (flowData->isReverse()) {
				flowData->reverseType = HTTP_TYPE_REQUEST;
				flowData->forwardType = HTTP_TYPE_RESPONSE;
			} else {
				flowData->forwardType = HTTP_TYPE_REQUEST;
				flowData->reverseType = HTTP_TYPE_RESPONSE;
			}

			processHttpRequest(end, dataEnd, flowData, aggregationStart, aggregationEnd);
		} else if (type == HTTP_TYPE_RESPONSE) {
		    // the first message observed was a HTTP response, that almost never be the case.
		    // usually that means we are at the start of the Packet observation process and
		    // were not able to observe the first Packets of a TCP connection which did start
		    // before the Packet observation.
			flowData->streamInfo->responseFirst = true;
			flowData->response->status = MESSAGE_RES_VERSION;
            // aggregate the response version
			if (flowData->response->version)
			    memcpy(flowData->response->version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));

			if (flowData->isReverse()) {
				flowData->reverseType = HTTP_TYPE_RESPONSE;
				flowData->forwardType = HTTP_TYPE_REQUEST;
			} else {
				flowData->forwardType = HTTP_TYPE_RESPONSE;
				flowData->reverseType = HTTP_TYPE_REQUEST;
			}

			uint8_t* requestCount = flowData->getFlowcount(true);
			uint8_t* responseCount = flowData->getFlowcount();
			// since we started with a response the next request should be put into a new flow
			flowData->request->status = MESSAGE_END;
			if (*requestCount <= *responseCount) {
                *requestCount = *responseCount + 1;
			}

			processHttpResponse(end, dataEnd, flowData, aggregationStart, aggregationEnd);
		}

		return 1;
	}

	/*
	 * this packet seems not the start of a http request or response, this can have several reasons, e.g.:
	 *  - this isn't a http stream
	 *  - this packet is a subsequent packet of a previous unreceived http request/response
	 */

	// skip package, do not aggregate payload
	DPRINTFL(MSG_DEBUG, "httpagg: no http traffic in this flow direction yet!");
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
int HttpAggregation::processHttpRequest(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	//process the request until we reach the end of the payload
	while (data<dataEnd) {
		start=end;
		http_status_t status = flowData->request->status;
		switch (status) {
        case MESSAGE_PROTO_UPGR: {
            // this state can only be reached if a protocol switch (HTTP response code 101) was initiated.
            // in this case we do not process the payload, but just aggregate it
            DPRINTFL(MSG_DEBUG, "httpagg: payload continuation after protocol switch (initiated by response code 101)");
            *aggregationEnd = dataEnd;
            return 1;
        }
		case MESSAGE_END: {
			// this state should never be reached. because new TCP payload should always be put in a new flow
			DPRINTFL(MSG_ERROR, "httpagg: reached invalid status, the message ended but we are still aggregating...");
#ifdef DEBUG
			THROWEXCEPTION("this point should be unreachable");
#endif
			break;
		}
		case NO_MESSAGE: {
			if (getRequestMethod(start, dataEnd, &start, &end)) {
				DPRINTFL(MSG_INFO, "httpagg: request method = '%.*s'", end-start, start);
				flowData->request->status = MESSAGE_REQ_METHOD;
	            // aggregate the request method
				if (flowData->request->method)
				    memcpy(flowData->request->method, start, min_(end-start, IPFIX_ELENGTH_httpRequestMethod));
			} else {
                DPRINTFL(MSG_DEBUG, "httpagg: request method did not end yet, wait for new payload");
                *aggregationEnd = start;
                flowData->request->status = flowData->request->status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
		case MESSAGE_REQ_METHOD: {
			if (getRequestUri(start, dataEnd, &start, &end)) {
				DPRINTFL(MSG_INFO, "httpagg: request uri = '%.*s'", end-start, start);
				flowData->request->status = MESSAGE_REQ_URI;
	            // aggregate the request uri
				if (flowData->request->uri)
				    memcpy(flowData->request->uri, start, min_(end-start, flowData->request->uriLength));
			} else {
			    DPRINTFL(MSG_DEBUG, "httpagg: request uri did not end yet, wait for new payload");
                *aggregationEnd = start;
                flowData->request->status = flowData->request->status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;
		}
		case MESSAGE_REQ_URI: {
			if (getRequestVersion(start, dataEnd, &start, &end)) {
				flowData->request->status = MESSAGE_REQ_VERSION;
				DPRINTFL(MSG_INFO, "httpagg: request version = '%.*s'", end-start, start);
                // aggregate the request version
				if (flowData->request->version)
				    memcpy(flowData->request->version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));
                eatCRLF(end, dataEnd, &end);
			} else {
			    DPRINTFL(MSG_DEBUG, "httpagg: request version did not end yet, wait for new payload");
                *aggregationEnd = start;
                flowData->request->status = flowData->request->status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;
		}
		case MESSAGE_REQ_VERSION: {
			if (processMessageHeader(start, dataEnd, &end, flowData)) {
			    DPRINTFL(MSG_INFO, "httpagg: processed message header successfully");
				if (flowData->request->entityTransfer == TRANSFER_NO_ENTITY) {
					// we are finished here since the message should not contain an entity
					flowData->request->status = MESSAGE_END;
					*aggregationEnd = end;
					if (end<dataEnd) {
						DPRINTFL(MSG_INFO, "httpagg: still %d bytes payload remaining, the packet may contain multiple requests", dataEnd-end);
						return 1;
					}
					return 1;
				} else {
					flowData->request->status = MESSAGE_HEADER;
				}
				//DPRINTFL(MSG_VDEBUG, "httpagg: message header fields = \n'%.*s'", end-start, start);
			} else {
				DPRINTFL(MSG_DEBUG, "httpagg: request header did not end yet, wait for new payload");
				*aggregationEnd = end;
				flowData->request->status = flowData->request->status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
		case MESSAGE_HEADER: {
			if (processEntity(start, dataEnd, &end, flowData)) {
				flowData->request->status = MESSAGE_END;
				*aggregationEnd = end;
				return 1;
			}
			*aggregationEnd = dataEnd;
			return 0;
			break;
		}
		default:
			THROWEXCEPTION("unhandled or unknown http request status: 0x%x", flowData->response->status);
		}
	}

	// end of the request hasnt been reached yet, aggregation of the
	*aggregationEnd = dataEnd;
	return 0;
}

/**
 * Parses a HTTP response. Tries to consume as much payload as possible. If no parsing errors occur and a remainder
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
int HttpAggregation::processHttpResponse(const char* data, const char* dataEnd, FlowData* flowData, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	bool stop = false;

	while (data<dataEnd && !stop) {
		start=end;
		http_status_t status = flowData->response->status;
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
            DPRINTFL(MSG_ERROR, "httpagg: reached invalid status, the message ended but we are still aggregating...");
#ifdef DEBUG
            THROWEXCEPTION("this point should be unreachable");
#endif
			return 1;
		}
		case NO_MESSAGE: {
			if (getResponseVersion(start, dataEnd, &start, &end)) {
				DPRINTFL(MSG_INFO, "httpagg: response version = '%.*s'", end-start, start);
				flowData->response->status = MESSAGE_RES_VERSION;
                // aggregate the response version
                if (flowData->response->version)
                    memcpy(flowData->response->version, start, min_(end-start, IPFIX_ELENGTH_httpVersionIdentifier));
			} else {
			    if (start == dataEnd) {
			        // skipping payload
			        *aggregationStart = dataEnd;
			        *aggregationEnd = dataEnd;
			    } else {
                    DPRINTFL(MSG_DEBUG, "httpagg: response version did not end yet, wait for new payload");
                    *aggregationEnd = start;
                    flowData->response->status = flowData->response->status | MESSAGE_FLAG_WAITING;
			    }
				return 0;
			}
			break;
		}
		case MESSAGE_RES_VERSION: {
			int code = getResponseCode(start, dataEnd, &start, &end);
			flowData->response->statusCode_ = code;
			if (code) {
				if (isMessageEntityForbidden(code))
					flowData->response->entityTransfer = TRANSFER_NO_ENTITY;
				if (code == 101) {
				    DPRINTFL(MSG_INFO, "httpagg: protocol switching status code detected");
				    // the status in both direction has to be changed to MESSAGE_PROTO_UPGR.
				    // but we still need to parse the response phrase...
				    // so for now the new state is only applied for the request.
				    flowData->request->status = MESSAGE_PROTO_UPGR;
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
				if (flowData->response->status)
				    flowData->response->status = MESSAGE_RES_CODE;
				DPRINTFL(MSG_INFO, "httpagg: response status code = '%.*s'", end-start, start);
                // aggregate the response code
				if (flowData->response->statusCode)
				    *flowData->response->statusCode = htons(code);
			} else {
                DPRINTFL(MSG_DEBUG, "httpagg: response code did not end yet, wait for new payload");
                *aggregationEnd = start;
                flowData->response->status = flowData->response->status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;

		}
		case MESSAGE_RES_CODE: {
			if (getResponsePhrase(start, dataEnd, &start, &end)) {
				flowData->response->status = MESSAGE_RES_PHRASE;
				DPRINTFL(MSG_INFO, "httpagg: response phrase = '%.*s'", end-start, start);
                // aggregate the response phrase
	            if (flowData->response->responsePhrase)
	                    memcpy(flowData->response->responsePhrase, start, min_(end-start, IPFIX_ELENGTH_httpResponsePhrase));

				if (flowData->response->statusCode_ == 101) {
				    DPRINTFL(MSG_INFO, "httpagg: skipping the rest of the payload because of protocol switching");
                    // if we are switching protocol, we are done with message parsing. from now on
				    // we just have to aggregate the payload
                    flowData->request->status = MESSAGE_PROTO_UPGR;
                    *aggregationEnd = dataEnd;
                    return 0;
				}
			} else {
                DPRINTFL(MSG_DEBUG, "httpagg: response phrase did not end yet, wait for new payload");
                *aggregationEnd = start;
                flowData->response->status = flowData->response->status | MESSAGE_FLAG_WAITING;
                return 0;
			}
			break;
		}
		case MESSAGE_RES_PHRASE: {
			if (processMessageHeader(start, dataEnd, &end, flowData)) {
				if (flowData->response->entityTransfer == TRANSFER_NO_ENTITY) {
					// we are finished here since the message should not contain an entity
					flowData->response->status = MESSAGE_END;
					if (end!=dataEnd) {
						DPRINTFL(MSG_INFO, "httpagg: still %d bytes payload remaining, the packet may contain multiple responses", dataEnd-data);
					}
					*aggregationEnd = end;
					return 1;
				} else {
					flowData->response->status = MESSAGE_HEADER;
				}
			} else {
				DPRINTFL(MSG_DEBUG, "httpagg: response header did not end yet, wait for new payload");
				*aggregationEnd = end;
				flowData->response->status = flowData->response->status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
		case MESSAGE_HEADER: {
			if (processEntity(start, dataEnd, &end, flowData)) {
				flowData->response->status = MESSAGE_END;
				*aggregationEnd = end;
				return 1;
			}
			*aggregationEnd = dataEnd;
			return 0;
			break;
		}
		default:
			THROWEXCEPTION("unhandled or unknown http response status: 0x%x", flowData->response->status);
		}
	}

	// end of response hasnt been reached yet
	*aggregationEnd = dataEnd;
	return 1;
}

/**
 * Parses the message header until we match ("\r\n" | "\n\n" | "\n\r\n") or reach the end of the packet.
 * See isValidMessageHeaderTerminatorSuffix() for the reason.
 * During the parsing process we check for the optional header fields "Transfer-Encoding" and "Content-Length", which
 * give us information about the length of the potential following entity field.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @return returns 0 if the message header did not end yet, 1 otherwise
 */
int HttpAggregation::processMessageHeader(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
	http_entity_transfer_t* transferType = flowData->getTransferType();
    *end = data;

	/*
	 * we try to match "\r\n", "\n\n" or "\n\r\n"
	 */
	while (data<=dataEnd-3) {
		const char *start = data;
		if (isValidMessageHeaderTerminatorSuffix(data, dataEnd, end)) {
			if (*transferType == TRANSFER_UNKNOWN ) {
			    if (flowData->isRequest()) {
                    // HTTP requests which do not supply a length header field cannot transfer a message body.
                    // From RFC 2616:
                    // "Closing the connection cannot be used to indicate the end of a request body,
                    // since that would leave no possibility for the server to send back a response."
                    *transferType = TRANSFER_NO_ENTITY;
			    } else {
		            // we assume the length of the message-body is determined by the server closing the connection
		            *transferType = TRANSFER_CONNECTION_BASED;
			    }
			}
			return 1;
		} else {
			if (*transferType != TRANSFER_CHUNKED &&
			        *transferType != TRANSFER_NO_ENTITY &&
			        !processMessageHeaderField(data, dataEnd, end, flowData)) {
				// too few characters left, stop processing
			    if (*end == dataEnd)
			        *end = start;
				return 0;
			}
		}

		if (*end <= data)
			data++;
		else
			data = *end;
		*end = start;
	}

	data = *end;
    while (data <= dataEnd) {
        *end = data;
        int len = dataEnd - data;
        switch (len) {
        case 2:
            if (!strncmp(data,"\r\n",len))
                return 0;
            else if (!strncmp(data,"\n\n",len)) {
                *end = dataEnd;
                if (*transferType == TRANSFER_UNKNOWN ) {
                    if (flowData->isRequest()) {
                        // HTTP requests which do not supply a length header field cannot transfer a message body.
                        // From RFC 2616:
                        // "Closing the connection cannot be used to indicate the end of a request body,
                        // since that would leave no possibility for the server to send back a response."
                        *transferType = TRANSFER_NO_ENTITY;
                    } else {
                        // we assume the length of the message-body is determined by the server closing the connection
                        *transferType = TRANSFER_CONNECTION_BASED;
                    }
                }
                return 1;
            }
            break;
        case 1:
            if (*data == '\r' || *data == '\n') {
                *end = data;
                return 0;
            }
            break;
        }
        data++;
    }
//	*end = dataEnd;

	return 0;
}



/**
 * Checks for a valid CRLF sequence at the beginning
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end On success used to store the position at which the parsing process stopped
 * @return Returns 1 if the sequence is valid, else otherwise
 */
int HttpAggregation::isValidMessageHeaderTerminatorSuffix(const char* data, const char* dataEnd, const char** end) {
	/*
	 * The four possible ways to terminate a http request are:
	 * - '\r\n\r\n'
	 * - '\r\n\n'
	 * - '\n\r\n'
	 * - '\n\n'
	 *
	 * Since '\n\r\n' and '\n\n' are common suffixes to all it should
	 * also be enough only to check for them.
	 */
	// TODO skip initial whitespaces
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
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @return
 */
int HttpAggregation::processMessageHeaderField(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
    http_entity_transfer* transferType = flowData->getTransferType();

    *end = data;
    const char* start = 0;
    int status = 0;
	if (*transferType != TRANSFER_CHUNKED &&
	        (status = matchField(data, dataEnd, &start, end, STR_CONTENT_LENGTH, SIZE_CONTENT_LENGTH))) {
	    if (status == FIELD_MATCH) {
	        if (start != *end) {
	            setContentLength(start, *end, flowData);
	            return 1;
	        } else
	            return 0;
	    }
	} else if ((status = matchField(data, dataEnd, &start, end, STR_TRANSFER_ENCODING, SIZE_TRANSFER_ENCODING))) {
	    if (status == FIELD_MATCH) {
             if (start != *end) {
                 setTransferEncoding(start, *end, flowData);
                 return 1;
             } else
                 return 0;
         }
	} else if (flowData->request->host && (status = matchField(data, dataEnd, &start, end, STR_HOST, SIZE_HOST))) {
        if (status == FIELD_MATCH) {
             if (start != *end) {
                 // aggregate request host header field
                 if (flowData->request->host)
                     memcpy(flowData->request->host, start, min_(*end-start, flowData->request->hostLength));
                 return 1;
             } else
                 return 0;
         }
    }

    return 1;
}

int HttpAggregation::matchField(const char* data, const char* dataEnd, const char** start, const char** end, const char* field, const size_t fieldSize) {
    if (tolower(*data) != field[0])
        return FIELD_NO_MATCH;

    // From RFC 2616, Section 4.2: Field names are case-insensitive.
    // Chunked Transfer-Encoding takes precedence over Content-Length

    const char* fstart = data;
    data++;
    size_t i = 1;
    while (data < dataEnd && i < fieldSize) {
        if (tolower(*data) == field[i]) {
            i++;
            data++;
        } else {
            break;
        }
    }
    if (i == fieldSize) {
        if (!getDelimitedText(data, dataEnd, start, end)) {
            *start = fstart;
            *end = fstart;
        }
        return FIELD_MATCH;
    }

    // only a part did match. because all header fields which we compare begin with
    // different characters it should be possible to skip the characters which were processed
    // by this method. therefore we store the position where we stopped
    *end = data;
    return FIELD_PARTIAL_MATCH;
}

/**
 * Stores the parsed value for the 'Transfer-Encoding' header field.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 */
void HttpAggregation::setTransferEncoding(const char* data, const char* dataEnd, FlowData* flowData) {
	if (!strncmp(data, "identity", dataEnd-data)) {
		// if transfer encoding is set to "identity" the message length is not affected by this field.
		// so we can ignore it
		return;
	}

	// if transfer encoding is not equal to "identity" the transfer-length is defined by use of the "chunked" transfer-coding

	if (flowData->isRequest()) {
		flowData->request->entityTransfer = TRANSFER_CHUNKED;
		DPRINTFL(MSG_INFO, "httpagg: the request transfer-length is defined by use of the \"chunked\" transfer-coding");
	} else {
		flowData->response->entityTransfer = TRANSFER_CHUNKED;
		DPRINTFL(MSG_INFO, "httpagg: the response transfer-length is defined by use of the \"chunked\" transfer-coding");
	}
}

/**
 * Stores the parsed value for the 'Content-Length' header field
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 */
void HttpAggregation::setContentLength(const char* data, const char* dataEnd, FlowData* flowData) {
	if (flowData->isRequest()) {
		flowData->request->entityTransfer = TRANSFER_CONTENT_LENGTH;
		flowData->request->contentLength = strtol(data, NULL, 10);
		DPRINTFL(MSG_INFO, "httpagg: set request content-length to %u", flowData->request->contentLength);
	} else {
		flowData->response->entityTransfer = TRANSFER_CONTENT_LENGTH;
		flowData->response->contentLength = strtol(data, NULL, 10);
		DPRINTFL(MSG_INFO, "httpagg: set response content-length to %u (parsed string = %.*s)", flowData->response->contentLength, dataEnd-data, data);
	}
}


/**
 * Parses the message body of a HTTP message. How the message is parsed depends on the transfer type:
 *  - case TRANSFER_NO_ENTITY: no length header fields were specified, no entity should exist... nothing to do
 *  - case TRANSFER_CHUNKED: 'Transfer-Encoding' was set in the message header. estimate the size of each chunk and skip those bytes
 *  - case TRANSFER_CONTENT_LENGTH: 'Content-Length' was set in the message header, a fixed value of bytes can be skipped
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param transferType Pointer to the message's #http_entity_transfer type
 * @return returns 1 if the entity end was reached, 0 otherwise
 */
int HttpAggregation::processEntity(const char* data, const char* dataEnd, const char** end, FlowData* flowData) {
	http_entity_transfer_t *transfer = flowData->getTransferType();

	*end = data;
	if (*transfer == TRANSFER_CHUNKED) {
		if (dataEnd-data<=0) {
			// no remaining payload, wait for new chunk
			*end = dataEnd;
			return 0;
		}
		uint32_t* contentLength;
		const char* start = data;

		if (flowData->isRequest()) contentLength = &flowData->request->contentLength;
		else contentLength = &flowData->response->contentLength;

		while (start<dataEnd) {
			uint32_t len = dataEnd-start;

			if (*contentLength<=0) {
				*contentLength = getChunkLength(start, dataEnd, end);
				start = *end;
				len = dataEnd - *end;
			}

			if (*contentLength>0) {
				if (*contentLength < len) {
					DPRINTFL(MSG_VDEBUG, "httpagg: this payload contains multiple chunks or multiple parts of chunks. current part range: %u to %u (%u bytes)", *end-data, (*end+*contentLength)-data, *contentLength);
					start = *end + *contentLength;
					*contentLength = 0;
					if (!eatCRLF(start, dataEnd, &start)) {
						DPRINTFL(MSG_ERROR, "httpagg: chunk did not end with a CRLF", *end-data, *end-data+len, len);
					}
				} else {
					DPRINTFL(MSG_VDEBUG, "httpagg: this payload contains a part of a chunk. current part range: %u to %u (%u bytes)", *end-data, *end-data+len, len);
					*contentLength = *contentLength-len;
					start = *end + len;
				}
				DPRINTFL(MSG_INFO, "httpagg: current remaining chunk size: %u", *contentLength);
			} else {
				start = *end;

				if (!eatCRLF(start, dataEnd, &start)) {
					// every chunk has to end with CRLF
					DPRINTFL(MSG_ERROR, "httpagg: error parsing chunked message");
					return 0;
				} else {
					// skip trailing entity-header fields
					bool endWithCRLF = true;
					while (start<dataEnd) {
						endWithCRLF = false;
						if (*start == '\r') {
							if (eatCRLF(start, dataEnd, &start))
								endWithCRLF = true;
							else
								start++;
						} else
							start++;
					}
					if (!endWithCRLF) {
						DPRINTFL(MSG_ERROR, "httpagg: error parsing chunked message");
					}
				}

				DPRINTFL(MSG_INFO, "httpagg: end of chunked message");

				*end = start;
				return 1;
			}
		}
		return 0;
	} else if (*transfer == TRANSFER_CONTENT_LENGTH) {
		uint32_t* contentLength = 0;
		if (flowData->isRequest()) {
			contentLength = &flowData->request->contentLength;
		} else {
			contentLength = &flowData->response->contentLength;
		}
		if (*contentLength<dataEnd-data) {
			DPRINTFL(MSG_DEBUG, "httpagg: the payload of the http response stream is bigger than specified in the header field, the packet may contain multiple messages");
			if (*contentLength>0) {
				*end = data + *contentLength;
				*contentLength = 0;
			} else {
				*end = data;
			}
			return 1;
		} else {
			*contentLength = *contentLength - (dataEnd-data);
			*end = dataEnd;
			DPRINTFL(MSG_INFO, "httpagg: processed %u bytes of the http entity, %u bytes left", dataEnd-data, *contentLength);
			if (*contentLength<=0)
				return 1; // we are finished
			else
				return 0;
		}
	} else if (*transfer == TRANSFER_CONNECTION_BASED) {
	    // we are finished when the connection closes, hence aggregate the whole payload
	    *end = dataEnd;
	    return 1;
	} else if (*transfer == TRANSFER_NO_ENTITY) {
		// the http message contains no entitiy
		DPRINTFL(MSG_DEBUG, "httpagg: http message contains no entity");
		return 1;
	} else {
		ASSERT_(*transfer != TRANSFER_UNKNOWN, "transfer type was not set, should never happen");
		DPRINTFL(MSG_DEBUG, "httpagg: no entity length was specified in the header fields");
	}

	return 1;
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
int HttpAggregation::getSpaceDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
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
int HttpAggregation::getCRLFDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
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
int HttpAggregation::getDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end, int max) {
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
 * Skips multiple consecutive line breaks
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @return
 */
int HttpAggregation::eatCRLF(const char* data, const char* dataEnd, const char** end) {
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
 * Tries to parse the length of a chunk.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param end Used to store the position at which the parsing process stopped
 * @return Returns the size of the chunk in bytes
 */
uint32_t HttpAggregation::getChunkLength(const char* data, const char* dataEnd, const char** end) {
	/*
	 * From RFC 2616, Section 3.6
	 * chunk          = chunk-size [ chunk-extension ] CRLF
	 * chunk-size     = 1*HEX
	 */
	const char* start = data;
	while (data<dataEnd) {
		if (*data == '\r') {
			if (data+1<dataEnd && *(data+1) == '\n') {
				uint32_t length = strtol(start, NULL, 16); // works also if chunk extensions are present
				DPRINTFL(MSG_INFO, "httpagg: start of a new chunk. chunk length = %u", length);
				*end = data+2;
				return length;
			}
			else
				break;
		}
		data++;
	}
	DPRINTFL(MSG_ERROR, "error parsing chunk size");
	*end=dataEnd;
	return 0;
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
int HttpAggregation::getRequestMethod(const char* data, const char* dataEnd, const char** start, const char** end) {
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
		DPRINTFL(MSG_INFO, "httpagg: invalid http method identifier : %.*s", *end-*start, *start);
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
int HttpAggregation::getRequestUri(const char* data, const char* dataEnd, const char** start, const char** end) {
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
int HttpAggregation::getRequestVersion(const char* data, const char* dataEnd, const char** start, const char** end) {
	if (getCRLFDelimitedText(data, dataEnd, start, end, 8)) {
		if (isVersion(*start, *end)) {
			return 1;
		}
		DPRINTFL(MSG_INFO, "httpagg: invalid http version specifier : '%.*s'", *end-*start, *start);
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
int HttpAggregation::getResponseVersion(const char* data, const char* dataEnd, const char** start, const char** end) {
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
		DPRINTFL(MSG_INFO, "httpagg: invalid http version specifier : %.*s", *end-*start, *start);
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
uint16_t HttpAggregation::getResponseCode(const char* data, const char* dataEnd, const char** start, const char** end) {
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
int HttpAggregation::getResponsePhrase(const char* data, const char* dataEnd, const char** start, const char** end) {
    return getCRLFDelimitedText(data, dataEnd, start, end);
}

/**
 * Checks if the passed payload starts with a request method or http version identifier.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends
 * @param type
 * @return Returns 1 if the passed payload starts with a request method or http version identifier, 0 otherwise
 */
int HttpAggregation::getRequestOrResponse(const char* data, const char* dataEnd, const char** start, const char** end, http_type_t* type)  {
	*type = HTTP_TYPE_UNKNOWN;
	*start = data;
	*end = data;

	if (getSpaceDelimitedText(data, dataEnd, start, end, 16)) {
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
int HttpAggregation::isRequest(const char* data, const char* dataEnd) {
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
int HttpAggregation::isResponse(const char* data, const char* dataEnd) {
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
int HttpAggregation::isVersion(const char* dataPtr, const char* dataEnd) {
	const int mlen = dataEnd-dataPtr;

	if (mlen != 8) {
		return 0;
	}

	if (!strncmp(dataPtr, "HTTP/", 4)) {
		return 1;
	}

	return 0;
}

/*
 *
 */
/**
 * Checks if the passed char range is a valid HTTP notification identifier
 * Currently HTTP notifications are unsupported, but may be used in future releases.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @return Returns 1 if the range contains a valid notification identifier
 */
int HttpAggregation::isNotification(const char* data, const char* dataEnd) {
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
 * Checks if the given status code forbids the use of an message entity
 * @param statusCode Code to check
 * @return Returns 1 if an entity is forbidden for this code, 0 otherwise
 */
int HttpAggregation::isMessageEntityForbidden(const int statusCode) {
	/*
	 * certain response codes forbid an entitiy
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
void HttpAggregation::copyToCharPointer(char** dst, const char* src, size_t size) {
	*dst = (char*)malloc(sizeof(char)*(size));;
	memcpy(*dst, src, size);
}

/*
 * Adds 'size' bytes of 'src' to the end of '*dst'
 */

/**
 * Adds 'size' bytes of 'src' to the end of '*dst'
 * @param dst Destination
 * @param src Source
 * @param dstLenth Current size of the destination buffer
 * @param size Number of bytes to add
 */
void HttpAggregation::addToCharPointer(char **dst, const char* src, size_t dstLenth, size_t size) {
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
void HttpAggregation::storeDataLeftOver(const char* data, const char* dataEnd, FlowData* flowData) {
    // not enough characters remaining to proceed processing now.
    // put remaining characters in the buffer and wait for new data to arrive.
    if (dataEnd-data > 0) {
        char **dst = flowData->isReverse() ? &flowData->streamInfo->reverseLine : &flowData->streamInfo->forwardLine;
        uint16_t size = dataEnd-data;
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
void HttpAggregation::initializeFlowData(FlowData* flowData, HttpStreamData* streamData) {
	flowData->streamInfo = streamData;
	flowData->forwardType = HTTP_TYPE_UNKNOWN;
	flowData->reverseType = HTTP_TYPE_UNKNOWN;

	flowData->request = new RequestData;
	flowData->request->method = 0;
	flowData->request->uri = 0;
	flowData->request->version = 0;
	flowData->request->host = 0;
	flowData->request->hostLength = 0;
	flowData->request->uriLength = 0;
	flowData->request->status = NO_MESSAGE;
	flowData->request->entityTransfer = TRANSFER_UNKNOWN;
	flowData->request->contentLength = 0;
	flowData->request->pipelinedRequestOffset = 0;
	flowData->request->pipelinedRequestOffsetEnd = 0;

	flowData->response = new ResponseData;
	flowData->response->version = 0;
	flowData->response->statusCode = 0;
	flowData->response->responsePhrase = 0;
	flowData->response->status = NO_MESSAGE;
	flowData->response->entityTransfer = TRANSFER_UNKNOWN;
	flowData->response->contentLength = 0;
    flowData->response->pipelinedResponseOffset = 0;
    flowData->response->pipelinedResponseOffsetEnd = 0;
    flowData->response->statusCode_ = 0;
}

/**
 * Initializes a new HttpStreamData structure
 */
HttpAggregation::HttpStreamData* HttpAggregation::initHttpStreamData() {
	HttpStreamData* streamBucket = new HttpStreamData;
	streamBucket->forwardFlows = 0;
	streamBucket->reverseFlows = 0;
	streamBucket->direction = 0;

	streamBucket->responseFirst = false;
	streamBucket->pipelinedRequest = false;
	streamBucket->pipelinedResponse = false;

	streamBucket->forwardLine = 0;
	streamBucket->reverseLine = 0;
	streamBucket->forwardLength = 0;
	streamBucket->reverseLength = 0;
	return streamBucket;
}

/**
 * Convenience function
 * @return true if the current payload is transferred in forward direction, false otherwise
 */
bool HttpAggregation::FlowData::isForward() {
    return *streamInfo->direction == 0;
}

/**
 * Convenience function
 * @return true if the current payload is transferred in reverse direction, false otherwise
 */
bool HttpAggregation::FlowData::isReverse() {
    return *streamInfo->direction == 1;
}

/**
 * Convenience function
 * @return true if the current type is known to be a request, false otherwise
 */
bool HttpAggregation::FlowData::isRequest() {
    return *getType() == HTTP_TYPE_REQUEST;
}

/**
 * Convenience function
 * @return true if the current type is known to be a response, false otherwise
 */
bool HttpAggregation::FlowData::isResponse() {
    return *getType() == HTTP_TYPE_RESPONSE;
}

/**
 * Get the @c http_type_t in the specified direction. Throws if the TCP stream direction was set incorrect.
 * @param oppositeDirection Specifies the direction. False for the current direction, true for the opposite direction. Default is false.
 * @return the type of
 */
HttpAggregation::http_type_t* HttpAggregation::FlowData::getType(bool oppositeDirection) {
    if (*streamInfo->direction == 0) {
        if (oppositeDirection)
            return &reverseType;
        else
            return &forwardType;
    }
    else if (*streamInfo->direction == 1) {
        if (oppositeDirection)
            return &forwardType;
        else
            return &reverseType;
    }
    THROWEXCEPTION("TCP stream direction was set incorrect");
    return NULL;
}

/**
 * Get the flow count in the specified direction. Throws if the HTTP type was set incorrect.
 * @param oppositeDirection Specifies the direction. False for the current direction, true for the opposite direction. Default is false.
 * @return a pointer to the flow counter in the specified direction
 */
uint8_t* HttpAggregation::FlowData::getFlowcount(bool oppositeDirection) {
    http_type_t type =*getType(oppositeDirection);
    if (type == forwardType) {
        return &(streamInfo->forwardFlows);
    } else if (type == this->reverseType) {
        return &(streamInfo->reverseFlows);
    }
    THROWEXCEPTION("HTTP type was set incorrect");
    return NULL;
}

/**
 * Get the @c http_entity_transfer_t in the specified direction. Throws if the HTTP type was set incorrect.
 * @return a pointer to the http_entity_transfer_t in the specified direction
 */
HttpAggregation::http_entity_transfer_t* HttpAggregation::FlowData::getTransferType() {
    if (isRequest())
        return &request->entityTransfer;
    else if (isResponse())
        return &response->entityTransfer;
    THROWEXCEPTION("HTTP type was set incorrect");
    return NULL;
}

/**
 * a string representation of the given http type
 * @param type type to represent
 * @return string representation of passed type
 */
const char* HttpAggregation::toString(http_type_t type) {
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
void HttpAggregation::printRange(const char* data, int range) {
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
uint32_t HttpAggregation::min_(uint32_t a, uint32_t b) {
    if (a < b)
        return a;
    else
        return b;
}

const char HttpAggregation::STR_CONTENT_LENGTH[] = "content-length:";
const char HttpAggregation::STR_TRANSFER_ENCODING[] = "transfer-encoding:";
const char HttpAggregation::STR_HOST[] = "host:";

void HttpAggregation::testFinishedMessage(FlowData* flowData) {
	http_type_t type = *flowData->getType();
	ASSERT_(type!=HTTP_TYPE_UNKNOWN, "http type unknown");
	ASSERT_(flowData->reverseType!=flowData->forwardType, "equal http types");

	if (type==HTTP_TYPE_REQUEST) {
		ASSERT_(flowData->request->status == MESSAGE_END, "message did not end");
		ASSERT_(!(flowData->request->status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT_(flowData->request->entityTransfer!=TRANSFER_UNKNOWN, "transfer type unknown");
		ASSERT_(flowData->response->status != MESSAGE_END, "response must not end before request");
	} else {
		ASSERT_(flowData->response->status == MESSAGE_END, "message did not end");
		ASSERT_(!(flowData->response->status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT_(flowData->response->entityTransfer!=TRANSFER_UNKNOWN, "transfer type unknown");
	}
}
