/*
 * Vermont Aggregator Subsystem
 * Copyright (C) 2014 Vermont Project
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
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start.
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 */
void HttpAggregation::detectHttp(const char** data, const char** dataEnd, FlowData* flowData, bool reverseDirection, const char** aggregationStart, const char** aggregationEnd) {
	msg(MSG_DEBUG, "detectHttp(): START in %s direction", reverseDirection ? "reverse" : "forward");
	msg(MSG_DEBUG, "detectHttp(): forward type = %s --- reverse type = %s", toString(flowData->forwardType), toString(flowData->reverseType));
	msg(MSG_DEBUG, "detectHttp(): forward Flows#=%d, reverse Flows#=%d", flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows);
	msg(MSG_DEBUG, "detectHttp(): request status=%X, response status=%X", flowData->request->status, flowData->response->status);

	*aggregationStart = *data;

	if (flowData->request->pipelinedRequestOffset && !reverseDirection) {
	    // we are continuing to process a packets payload which has been processed before.
	    // this means this packet contains multiple requests
		msg(MSG_INFO, "detectHttp(): http detection is starting with %u bytes offset", flowData->request->pipelinedRequestOffset);
		*aggregationStart = *data+flowData->request->pipelinedRequestOffset;
		flowData->request->pipelinedRequestOffset = 0;
	} else if (!flowData->request->pipelinedRequestOffset) {
		uint16_t plen = *dataEnd - *data;

		// check if the last processed packet in this direction has some left over bytes of payload which
		// have to be reconsidered in combination with the current payload
		if (reverseDirection && flowData->streamInfo->reverseLength>0 && flowData->streamInfo->reverseLine) {
		    // combine the bytes left over with the current payload
			char *combined = 0;
			copyToCharPointer(&combined, flowData->streamInfo->reverseLine, flowData->streamInfo->reverseLength, false);
			addToCharPointer(&combined, *data, flowData->streamInfo->reverseLength, plen);

			// set the pointers to the new memory area
			*data = combined;
			*aggregationStart = combined;
			*dataEnd = combined+flowData->streamInfo->reverseLength+plen;

			msg(MSG_INFO, "detectHttp(): %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->reverseLength, *dataEnd-*data);

			flowData->streamInfo->reverseLength = 0;
			free(flowData->streamInfo->reverseLine);
		} else if (!reverseDirection && flowData->streamInfo->forwardLength>0 && flowData->streamInfo->forwardLine) {
		    // combine the bytes left over with the current payload
			char* combined;
			copyToCharPointer(&combined, flowData->streamInfo->forwardLine, flowData->streamInfo->forwardLength, false);
			addToCharPointer(&combined, *data, flowData->streamInfo->forwardLength, plen);

			// set the pointers to the new memory area
			*data = combined;
			*aggregationStart = combined;
			*dataEnd = combined+flowData->streamInfo->forwardLength+plen;

			msg(MSG_INFO, "detectHttp(): %u bytes of previously buffered payload are combined with the current payload. new payload size: %u bytes", flowData->streamInfo->forwardLength, *dataEnd-*data);

			flowData->streamInfo->forwardLength = 0;
			free(flowData->streamInfo->forwardLine);
		}
	}

	if (!flowData->request->status && !flowData->response->status && flowData->forwardType == HTTP_TYPE_UNKNOWN) {
		/*
		 *  fresh start, no request or response has been detected yet.
		 *  if we start with a http request it should be possible to detect pipelined requests,
		 *  provided this is the first transmitted request.
		 */

		msg(MSG_INFO, "detectHttp(): processing new http traffic");

		if (!processNewHttpTraffic(*aggregationStart, *dataEnd, flowData, reverseDirection, aggregationStart, aggregationEnd))
		    return; // this message is not a start of a http request or response

	} else {
		if (flowData->request->status == MESSAGE_END && flowData->response->status == MESSAGE_END)
			THROWEXCEPTION("response and request are already finished, this flow should have been exported!");

		if (flowData->reverseType == flowData->forwardType || flowData->reverseType == HTTP_TYPE_UNKNOWN || flowData->forwardType == HTTP_TYPE_UNKNOWN)
			THROWEXCEPTION("http types were set faulty, this should never happen!");

		http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;

		if (type == HTTP_TYPE_RESPONSE)
			processHttpResponse(*aggregationStart, *dataEnd, flowData, reverseDirection, aggregationStart, aggregationEnd);
		else if (type == HTTP_TYPE_REQUEST)
			processHttpRequest(*aggregationStart, *dataEnd, flowData, reverseDirection, aggregationStart, aggregationEnd);
	}

    http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;

    if (type == HTTP_TYPE_RESPONSE) {
        if (flowData->response->status & MESSAGE_FLAG_WAITING) { // more payload required to finish processing
            // copy the bytes left over (i.e. the bytes of payload which could not be parsed) into the buffer
            storeDataLeftOver(*aggregationEnd, *dataEnd, flowData, reverseDirection);
            flowData->response->status &= ~MESSAGE_FLAG_WAITING;
        } else if (flowData->response->status == MESSAGE_END) { // response message ended
            msg(MSG_INFO, "detectHttp(): http response ended");
            testFinishedMessage(flowData, reverseDirection);
            if (reverseDirection) flowData->streamInfo->reverseFlows++;
            else flowData->streamInfo->forwardFlows++;
        }
    } else if (type == HTTP_TYPE_REQUEST) {
        if (flowData->request->status & MESSAGE_FLAG_WAITING) { // more payload required to finish processing
            // copy the bytes left over (i.e. the bytes of payload which could not be parsed) into the buffer
            storeDataLeftOver(*aggregationEnd, *dataEnd, flowData, reverseDirection);
            flowData->request->status &= ~MESSAGE_FLAG_WAITING;
        } else if (flowData->request->status == MESSAGE_END) { // request message ended
            msg(MSG_INFO, "detectHttp(): http request ended");
            testFinishedMessage(flowData, reverseDirection);
            if (reverseDirection) flowData->streamInfo->reverseFlows++;
            else flowData->streamInfo->forwardFlows++;
        }
    }

	msg(MSG_DEBUG, "detectHttp(): END");
	msg(MSG_DEBUG, "detectHttp(): forward Flows#=%d, reverse Flows#=%d", flowData->streamInfo->forwardFlows, flowData->streamInfo->reverseFlows);
	msg(MSG_DEBUG, "detectHttp(): request status=%X, response status=%X", flowData->request->status, flowData->response->status);
}

/**
 * Checks if the payload starts with a valid http method or a http version code identifier.
 * On success the current flow direction can be classified as request and the other as response
 * or vice versa, depending on the identifier. Afterwards the rest of the payload is processed.
 *
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 */
int HttpAggregation::processNewHttpTraffic(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	http_type_t type = HTTP_TYPE_UNKNOWN;

	// check for a request or response at the beginning.
	if (getRequestOrResponse(data, dataEnd, &start, &end, &type)) {
		msg(MSG_INFO, "detectHttp(): payload contains a http %s: '%.*s'", toString(type), end-start, start);
		if (type == HTTP_TYPE_REQUEST) {
			flowData->request->status = MESSAGE_REQ_METHOD;
			copyToCharPointer(&flowData->request->method, start, end-start, true);

			if (reverseDirection) {
				flowData->reverseType = HTTP_TYPE_REQUEST;
				flowData->forwardType = HTTP_TYPE_RESPONSE;
			} else {
				flowData->forwardType = HTTP_TYPE_REQUEST;
				flowData->reverseType = HTTP_TYPE_RESPONSE;
			}

			processHttpRequest(end, dataEnd, flowData, reverseDirection, aggregationStart, aggregationEnd);
		} else if (type == HTTP_TYPE_RESPONSE) {
			flowData->streamInfo->responseFirst = true;
			flowData->response->status = MESSAGE_RES_VERSION;
			copyToCharPointer(&flowData->response->version, start, end-start, true);

			if (reverseDirection) {
				flowData->reverseType = HTTP_TYPE_RESPONSE;
				flowData->forwardType = HTTP_TYPE_REQUEST;
			} else {
				flowData->forwardType = HTTP_TYPE_RESPONSE;
				flowData->reverseType = HTTP_TYPE_REQUEST;
			}

			// since we started with a response the next request should be put into a new flow
			flowData->request->status = MESSAGE_END;
			if (reverseDirection) flowData->streamInfo->forwardFlows++;
			else flowData->streamInfo->reverseFlows++;

			processHttpResponse(end, dataEnd, flowData, reverseDirection, aggregationStart, aggregationEnd);
		}

		return 1;
	}

	/*
	 * this packet is not the start of a http request or response, this can have several reasons:
	 *  - this isn't a http stream
	 *  - this packet is a subsequent packet of a previous unreceived http request/response
	 *  - the payload in the packet is too short, but that is unlikely
	 */

	// skip package, do not aggregate anything
	msg(MSG_INFO, "detectHttp(): no http traffic in this flow direction yet!");
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
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 * @return Returns 1 if the end of the message was reached, 0 otherwise
 */
int HttpAggregation::processHttpRequest(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	bool stop = false;

	//process the request until we reach the end of the payload
	while (data<dataEnd && !stop) {
		start=end;
		http_status_t status = flowData->request->status;
		switch (status) {
		case MESSAGE_ENTITY:
		case MESSAGE_END: {
			// nothing to do here, message was parsed completely. but it seems the message was malformed
			msg(MSG_INFO, "detectHttp(): invalid http request data! unexpected end of payload");
			stop = true;
			THROWEXCEPTION("hada");
			break;
		}
		case NO_MESSAGE: {
			if (getRequestMethod(start, dataEnd, &start, &end)) {
				msg(MSG_INFO, "detectHttp(): request method = '%.*s'", end-start, start);
				flowData->request->status = MESSAGE_REQ_METHOD;
				copyToCharPointer(&flowData->request->method, start, end-start, true);
			} else {
				// the message seems not to start with a valid http request version identifier.
				// we assume this packet is not a http packet, therefore skip it
				msg(MSG_INFO, "detectHttp(): warning: potential http request packet has been skipped. reason: packet did not start with a valid request method identfier");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;
		}
		case MESSAGE_REQ_METHOD: {
			if (getRequestUri(start, dataEnd, &start, &end)) {
				msg(MSG_INFO, "detectHttp(): request uri = '%.*s'", end-start, start);
				flowData->request->status = MESSAGE_REQ_URI;
				copyToCharPointer(&flowData->request->uri, start, end-start, true);
			} else {
				// first line of a request should be processed without problems, even with smaller packet sizes.
				// therefore skip this packet. // TODO stimmt nicht bei multiple requests
				msg(MSG_INFO, "detectHttp(): warning: potential http request packet has been skipped. reason: uri could not be parsed");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;
		}
		case MESSAGE_REQ_URI: {
			if (getRequestVersion(start, dataEnd, &start, &end)) {
				flowData->request->status = MESSAGE_REQ_VERSION;
				msg(MSG_INFO, "detectHttp(): request version = '%.*s'", end-start, start);
				copyToCharPointer(&flowData->request->version, start, end-start, true);
			} else {
				// first line of a request should be processed without problems, even with smaller packet sizes.
				// therefore skip this packet. // TODO stimmt nicht bei multiple requests
				msg(MSG_INFO, "detectHttp(): warning: potential http request packet has been skipped. reason: http version could not be parsed");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;
		}
		case MESSAGE_REQ_VERSION: {
			if (processMessageHeader(start, dataEnd, &end, flowData, reverseDirection)) {
				if (flowData->request->entityTransfer == TRANSFER_NO_ENTITY) {
					// we are finished here since the message should not contain an entity
					flowData->request->status = MESSAGE_END;
					*aggregationEnd = end;
					if (end<dataEnd) {
						msg(MSG_INFO, "detectHttp(): still %d bytes payload remaining, the packet may contain multiple requests", dataEnd-end);
						return 1;
					}
					return 1;
				} else {
					flowData->request->status = MESSAGE_HEADER;
				}
				//msg(MSG_VDEBUG, "detectHttp(): message header fields = \n'%.*s'", end-start, start);
			} else {
				msg(MSG_INFO, "detectHttp(): request header did not end yet, wait for new payload");
				*aggregationEnd = start;
				flowData->request->status = flowData->request->status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
		case MESSAGE_HEADER: {
			if (processEntity(start, dataEnd, &end, flowData, reverseDirection)) {
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
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @param aggregationStart Used to store the position in the payload from which the aggregation should start
 * @param aggregationEnd Used to store the position in the payload at which the aggregation should stop.
 * @return Returns 1 if the end of the message was reached, 0 otherwise
 */
int HttpAggregation::processHttpResponse(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection, const char** aggregationStart, const char** aggregationEnd) {
	const char* start = data;
	const char* end = data;

	bool stop = false;

	while (data<dataEnd && !stop) {
		start=end;
		http_status_t status = flowData->response->status;
		switch (status) {
		case MESSAGE_ENTITY:
		case MESSAGE_END: {
			// nothing to do here, message was parsed completely. but it seems the message was malformed
			msg(MSG_INFO, "detectHttp(): invalid http response data! unexpected end of payload");
			//THROWEXCEPTION("should not be reached");
			return 1;
			break;
		}
		case NO_MESSAGE: {
			if (getResponseVersion(start, dataEnd, &start, &end)) {
				msg(MSG_INFO, "detectHttp(): response version = '%.*s'", end-start, start);
				flowData->response->status = MESSAGE_RES_VERSION;
				copyToCharPointer(&flowData->response->version, start, end-start, true);
			} else {
				// the message seems not to start with a valid http response version identifier.
				// we assume this packet is not a http packet, therefore skip it
				msg(MSG_INFO, "detectHttp(): warning: potential http response packet has been skipped. reason: packet did not start with a valid http version identfier");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;
		}
		case MESSAGE_RES_VERSION: {
			int code = getResponseCode(start, dataEnd, &start, &end);
			if (code) {
				if (isMessageEntityForbidden(code))
					flowData->response->entityTransfer = TRANSFER_NO_ENTITY;
				flowData->response->status = MESSAGE_RES_CODE;
				msg(MSG_INFO, "detectHttp(): response status code = '%.*s'", end-start, start);
				copyToCharPointer(&flowData->response->statusCode, start, end-start, true);
			} else {
				// first line of a response should be processed without problems, even with smaller packet sizes.
				// therefore skip this packet.
				msg(MSG_INFO, "detectHttp(): warning: potential http response packet has been skipped. reason: status code could not be parsed");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;

		}
		case MESSAGE_RES_CODE: {
			if (getResponsePhrase(start, dataEnd, &start, &end)) {
				flowData->response->status = MESSAGE_RES_PHRASE;
				msg(MSG_INFO, "detectHttp(): response phrase = '%.*s'", end-start, start);
				copyToCharPointer(&flowData->response->responsePhrase, start, end-start, true);
			} else {
				// first line of a response should be processed without problems, even with smaller packet sizes.
				// therefore skip this packet.
				msg(MSG_INFO, "detectHttp(): warning: potential http response packet has been skipped. reason: response phrase could not be parsed");
				*aggregationEnd = dataEnd;
				return 0;
			}
			break;
		}
		case MESSAGE_RES_PHRASE: {
			if (processMessageHeader(end, dataEnd, &end, flowData, reverseDirection)) {
				if (flowData->response->entityTransfer == TRANSFER_NO_ENTITY) {
					// we are finished here since the message should not contain an entity
					flowData->response->status = MESSAGE_END;
					if (end!=dataEnd) {
						msg(MSG_INFO, "detectHttp(): skipped %d bytes of the packet payload, because the http response was malformed.", dataEnd-data);
					}
					*aggregationEnd = end;
					return 1;
				} else {
					flowData->response->status = MESSAGE_HEADER;
				}
				//msg(MSG_VDEBUG, "detectHttp(): message header fields = \n'%.*s'", end-start, start);
			} else {
				msg(MSG_INFO, "detectHttp(): response header did not end yet, wait for new payload");
				*aggregationEnd = start;
				flowData->response->status = flowData->response->status | MESSAGE_FLAG_WAITING;
				return 0;
			}
			break;
		}
		case MESSAGE_HEADER: {
			if (processEntity(end, dataEnd, &end, flowData, reverseDirection)) {
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

	// TODO if message header is really big and packet size small it might be that
	// the message header exceeds a single packet. this case isn't handled

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
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @return
 */
int HttpAggregation::processMessageHeader(const char* data, const char* dataEnd, const char** end, FlowData* flowData, bool reverseDirection) {
	http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;
	http_entity_transfer_t* transferType = (type == HTTP_TYPE_REQUEST) ? &flowData->request->entityTransfer : &flowData->response->entityTransfer;

	/*
	 * we try to match "\r\n", "\n\n" or "\n\r\n"
	 */
	while (data<=dataEnd-3) {
		const char *start = data;
		if (isValidMessageHeaderTerminatorSuffix(data, dataEnd, end)) {
			if (*transferType == TRANSFER_UNKNOWN)
				*transferType = TRANSFER_NO_ENTITY;
			return 1;
		} else {
			if (!processMessageHeaderField(data, dataEnd, end, flowData, transferType, reverseDirection) && *end == dataEnd) {
				// too few characters left, stop processing
				*end = start;
				return 0;
			}
		}

		if (*end <= data)
			data++;
		else
			data = *end;
	}
	*end = dataEnd;
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
		} else if (*data=='n'){
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
 * @param transferType Pointer to the message's #http_entity_transfer type
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @return
 */
int HttpAggregation::processMessageHeaderField(const char* data, const char* dataEnd, const char** end, FlowData* flowData, http_entity_transfer* transferType, bool reverseDirection) {
	// Chunked Transfer-Encoding takes precedence over Content-Length
	if (*transferType != TRANSFER_CHUNKED && *data == STR_CONTENT_LENGTH[0]) {
		data++;
		int i = 1;
		while (data<dataEnd && i<SIZE_CONTENT_LENGTH) {
			if (*data == STR_CONTENT_LENGTH[i]) {
				i++;
				data++;
			} else {
				break;
			}
		}
		if (i==SIZE_CONTENT_LENGTH) {
			const char *start = data;
			if (getDelimitedText(data, dataEnd, &start, end)) {
				setContentLength(start, *end, flowData, reverseDirection);
				return 1;
			}
		}
	} else if (*data == STR_TRANSFER_ENCODING[0]) {
		data++;
		int i = 1;
		while (data<dataEnd && i<SIZE_TRANSFER_ENCODING) {
			if (*data == STR_TRANSFER_ENCODING[i]) {
				i++;
				data++;
			} else {
				break;
			}
		}
		if (i==SIZE_TRANSFER_ENCODING) {
			const char *start = data;
			if (getDelimitedText(data, dataEnd, &start, end)) {
				setTransferEncoding(start, *end, flowData, reverseDirection);
				return 1;
			}
		}
	}
	// all processed characters can be skipped since we do not process any line delimiter
	*end = data;
	return 0;
}

/**
 * Stores the parsed value for the 'Transfer-Encoding' header field.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param reverseDirection Whether the current flow is in reverse direction or not
 */
void HttpAggregation::setTransferEncoding(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection) {
	if (!strncmp(data, "identity", dataEnd-data)) {
		// if transfer encoding is set to "identity" the message length is not affected by this field.
		// so we can ignore it
		return;
	}

	// if transfer encoding is not equal to "identity" the transfer-length is defined by use of the "chunked" transfer-coding

	http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;

	if (type == HTTP_TYPE_REQUEST) {
		flowData->request->entityTransfer = TRANSFER_CHUNKED;
		msg(MSG_INFO, "detectHttp(): the request transfer-length is defined by use of the \"chunked\" transfer-coding");
	} else {
		flowData->response->entityTransfer = TRANSFER_CHUNKED;
		msg(MSG_INFO, "detectHttp(): the response transfer-length is defined by use of the \"chunked\" transfer-coding");
	}
}

/**
 * Stores the parsed value for the 'Content-Length' header field
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param flowData Pointer to the FlowData structure which contains information about the current flow
 * @param reverseDirection Whether the current flow is in reverse direction or not
 */
void HttpAggregation::setContentLength(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection) {
	http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;

	if (type == HTTP_TYPE_REQUEST) {
		flowData->request->entityTransfer = TRANSFER_CONTENT_LENGTH;
		flowData->request->contentLength = strtol(data, NULL, 10);
		msg(MSG_INFO, "detectHttp(): set request content-length to %u", flowData->request->contentLength);
	} else {
		flowData->response->entityTransfer = TRANSFER_CONTENT_LENGTH;
		flowData->response->contentLength = strtol(data, NULL, 10);
		msg(MSG_INFO, "detectHttp(): set response content-length to %u (parsed string = %.*s)", flowData->response->contentLength, dataEnd-data, data);
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
 * @param reverseDirection Whether the current flow is in reverse direction or not
 * @return
 */
int HttpAggregation::processEntity(const char* data, const char* dataEnd, const char** end, FlowData* flowData, bool reverseDirection) {
	http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;
	http_entity_transfer_t transfer = type == HTTP_TYPE_REQUEST ? flowData->request->entityTransfer : flowData->response->entityTransfer;

	*end = data;

	if (transfer == TRANSFER_CHUNKED) {
		if (dataEnd-data<=0) {
			// no remaining payload, wait for new chunk
			*end = dataEnd;
			return 0;
		}
		uint32_t* contentLength;
		const char* start = data;

		if (type == HTTP_TYPE_REQUEST) contentLength = &flowData->request->contentLength;
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
					msg(MSG_INFO, "detectHttp(): this payload contains multiple chunks or multiple parts of chunks. current part range: %u to %u (%u bytes)", *end-data, (*end+*contentLength)-data, *contentLength);
					start = *end + *contentLength;
					*contentLength = 0;
					if (!eatCRLF(start, dataEnd, &start)) {
						msg(MSG_INFO, "detectHttp(): chunk did not end with a CRLF", *end-data, *end-data+len, len);
					}
				} else {
					msg(MSG_INFO, "detectHttp(): this payload contains a part of a chunk. current part range: %u to %u (%u bytes)", *end-data, *end-data+len, len);
					*contentLength = *contentLength-len;
					start = *end + len;
				}
				msg(MSG_INFO, "detectHttp(): current remaining chunk size: %u", *contentLength);
			} else {
				start = *end;

				if (!eatCRLF(start, dataEnd, &start)) {
					// every chunk has to end with CRLF
					msg(MSG_INFO, "detectHttp(): error parsing chunked message");
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
						msg(MSG_INFO, "detectHttp(): error parsing chunked message");

					}
				}

				msg(MSG_INFO, "detectHttp(): end of chunked message");

				*end = start;
				return 1;
			}
		}
		return 0;
	} else if (transfer == TRANSFER_CONTENT_LENGTH) {
		uint32_t* contentLength = 0;
		if (type == HTTP_TYPE_REQUEST) {
			contentLength = &flowData->request->contentLength;
		} else {
			contentLength = &flowData->response->contentLength;
		}
		if (*contentLength<dataEnd-data) {
			msg(MSG_INFO, "detectHttp(): warning: the payload of the http response stream is bigger than specified in the header field! stopping here!");
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
			msg(MSG_INFO, "detectHttp(): processed %u bytes of the http entity, %u bytes left", dataEnd-data, *contentLength);
			if (*contentLength<=0)
				return 1; // we are finished
			else
				return 0;
		}
	} else if (transfer == TRANSFER_NO_ENTITY) {
		// the http message contains no entitiy
		msg(MSG_INFO, "detectHttp(): http message contains no entity");
		return 1;
	} else {
		ASSERT_(transfer != TRANSFER_UNKNOWN, "transfer type was not set, should never happen");
		msg(MSG_INFO, "detectHttp(): no entity length was specified in the header fields");
	}

	return 1;
}

/**
 * Searches for text delimited by a whitespace. Initial spaces are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position where the first non whitespace character, regardless
 * if a delimited text was found. If the whole payload consists of spaces, the pointer points to
 * the end of the payload
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HttpAggregation::getSpaceDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end) {
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
 * Searches for text delimited by a whitespace, LF or CR. Initial delimiters are skipped.
 * @param data Pointer to the payload to be parsed
 * @param dataEnd Pointer to the end of the payload to be parsed
 * @param start Used to store the position at which the parsed text begins
 * @param end Used to store the position at which the parsed text ends. If no delimited text is
 * found the pointer points to the end of the payload
 * @return Returns 1 if text was found, 0 otherwise
 */
int HttpAggregation::getDelimitedText(const char* data, const char* dataEnd, const char** start, const char** end) {
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
				msg(MSG_INFO, "detectHttp(): start of a new chunk. chunk length = %u\n", length);
				*end = data+2; // FIXME to check
				return length;
			}
			else
				break;
		}
		data++;
	}
	msg(MSG_INFO, "error parsing chunk size");
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
		msg(MSG_INFO, "detectHttp(): invalid http method identifier : %.*s", *end-*start, *start);
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
	if (getDelimitedText(data, dataEnd, start, end)) {
		if (isVersion(*start, *end)) {
		    eatCRLF(*end, dataEnd, end);
			return 1;
		}
		msg(MSG_INFO, "detectHttp(): invalid http version specifier : %.*s", *end-*start, *start);
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
	if (getSpaceDelimitedText(data, dataEnd, start, end)) {
		if (isResponse(*start, *end)) {
			return 1;
		}
		msg(MSG_INFO, "detectHttp(): invalid http version specifier : %.*s", *end-*start, *start);
	}
	// if nothing did match this payload is invalid
	// skip this packet
	*start = dataEnd;
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
	if (getSpaceDelimitedText(data, dataEnd, start, end)) {
		if (*end-*start!=3)
			return 0;
		const char *codeEnd = *end;
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
    if (getDelimitedText(data, dataEnd, start, end)) {
        eatCRLF(*end, dataEnd, end);
        return 1;
    }
	return 0;
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
	int isHttpRequestOrReply = 0;
	*type = HTTP_TYPE_UNKNOWN;
	*start = data;
	*end = data;

	if (getSpaceDelimitedText(data, dataEnd, start, end)) {
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

// HTTP Method Identifiers were taken from Wireshark
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

	// ICY isnt relevant currently
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
	 */
	if ((statusCode >= 100 && statusCode<200) ||
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
 * @param terminator Specifies if the string terminator '\0' should be added at the end
 */
void HttpAggregation::copyToCharPointer(char** dst, const char* src, size_t size, bool terminator) {
	if (terminator)
		*dst = (char*)malloc(sizeof(char)*(size+1));
	else
		*dst = (char*)malloc(sizeof(char)*(size));;
	memcpy(*dst, src, size);
	if (terminator)
		(*dst)[size]='\0';
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
void HttpAggregation::storeDataLeftOver(const char* data, const char* dataEnd, FlowData* flowData, bool reverseDirection) {
    // not enough characters remaining to proceed processing now.
    // put remaining characters in the buffer and wait for new data to arrive.
    if (dataEnd-data > 0) {
        char **dst = reverseDirection ? &flowData->streamInfo->reverseLine : &flowData->streamInfo->forwardLine;
        uint16_t size = dataEnd-data;
        copyToCharPointer(dst, data, size, false);
        if (reverseDirection) flowData->streamInfo->reverseLength = size;
        else flowData->streamInfo->forwardLength = size;
        msg(MSG_INFO, "detectHttp(): copying %u bytes of left over payload to buffer.", size);
        msg(MSG_INFO, "detectHttp(): storing message : %.*s", size, data);
    } else {
        msg(MSG_FATAL, "detectHttp(): something went wrong!");
    }
}

/**
 * Initializes the given FlowData structure
 */
void HttpAggregation::initializeFlowData(FlowData* flowData, StreamData* streamData) {
	flowData->streamInfo = streamData;
	flowData->forwardType = HTTP_TYPE_UNKNOWN;
	flowData->reverseType = HTTP_TYPE_UNKNOWN;

	flowData->request = new RequestData;
	flowData->request->method = 0;
	flowData->request->uri = 0;
	flowData->request->version = 0;
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
}

/**
 * Initializes a new StreamData structure
 */
HttpAggregation::StreamData* HttpAggregation::initStreamBucket() {
	StreamData* streamBucket = new StreamData;
	streamBucket->forwardFlows = 0;
	streamBucket->reverseFlows = 0;

	streamBucket->responseFirst = false;
	streamBucket->pipelinedRequest = false;

	streamBucket->forwardLine = 0;
	streamBucket->reverseLine = 0;
	streamBucket->forwardLength = 0;
	streamBucket->reverseLength = 0;
	return streamBucket;
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

const char HttpAggregation::STR_CONTENT_LENGTH[] = "Content-Length:";
const char HttpAggregation::STR_TRANSFER_ENCODING[] = "Transfer-Encoding:";

// HTTP Status Codes - Taken from Wireshark
/* --- HTTP Status Codes */
/* Note: The reference for uncommented entries is RFC 2616 */
const HttpAggregation::value_string vals_status_code[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 102, "Processing" },                     /* RFC 2518 */
	{ 199, "Informational - Others" },

	{ 200, "OK"},
	{ 201, "Created"},
	{ 202, "Accepted"},
	{ 203, "Non-authoritative Information"},
	{ 204, "No Content"},
	{ 205, "Reset Content"},
	{ 206, "Partial Content"},
	{ 207, "Multi-Status"},                    /* RFC 4918 */
    { 226, "IM Used"},                         /* RFC 3229 */
	{ 299, "Success - Others"},

	{ 300, "Multiple Choices"},
	{ 301, "Moved Permanently"},
	{ 302, "Found"},
	{ 303, "See Other"},
	{ 304, "Not Modified"},
	{ 305, "Use Proxy"},
	{ 307, "Temporary Redirect"},
	{ 399, "Redirection - Others"},

	{ 400, "Bad Request"},
	{ 401, "Unauthorized"},
	{ 402, "Payment Required"},
	{ 403, "Forbidden"},
	{ 404, "Not Found"},
	{ 405, "Method Not Allowed"},
	{ 406, "Not Acceptable"},
	{ 407, "Proxy Authentication Required"},
	{ 408, "Request Time-out"},
	{ 409, "Conflict"},
	{ 410, "Gone"},
	{ 411, "Length Required"},
	{ 412, "Precondition Failed"},
	{ 413, "Request Entity Too Large"},
	{ 414, "Request-URI Too Long"},
	{ 415, "Unsupported Media Type"},
	{ 416, "Requested Range Not Satisfiable"},
	{ 417, "Expectation Failed"},
	{ 418, "I'm a teapot"},                    /* RFC 2324 */
	{ 422, "Unprocessable Entity"},            /* RFC 4918 */
	{ 423, "Locked"},                          /* RFC 4918 */
	{ 424, "Failed Dependency"},               /* RFC 4918 */
    { 426, "Upgrade Required"},                /* RFC 2817 */
    { 428, "Precondition Required"},           /* RFC 6585 */
    { 429, "Too Many Requests"},               /* RFC 6585 */
    { 431, "Request Header Fields Too Large"}, /* RFC 6585 */
	{ 499, "Client Error - Others"},

	{ 500, "Internal Server Error"},
	{ 501, "Not Implemented"},
	{ 502, "Bad Gateway"},
	{ 503, "Service Unavailable"},
	{ 504, "Gateway Time-out"},
	{ 505, "HTTP Version not supported"},
	{ 507, "Insufficient Storage"},            /* RFC 4918 */
    { 511, "Network Authentication Required"}, /* RFC 6585 */
	{ 599, "Server Error - Others"},

	{ 0, 	NULL}
};

void HttpAggregation::testFinishedMessage(FlowData* flowData, bool reverseDirection) {
	http_type_t type = reverseDirection ? flowData->reverseType : flowData->forwardType;
	ASSERT_(type!=HTTP_TYPE_UNKNOWN, "http type unknown");
	ASSERT_(flowData->reverseType!=flowData->forwardType, "equal http types");

	if (type==HTTP_TYPE_REQUEST) {
		ASSERT_(flowData->request->status == MESSAGE_END, "message did not end");
		ASSERT_(!(flowData->request->status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT_(flowData->request->entityTransfer!=TRANSFER_UNKNOWN, "transfer type unknown");
		ASSERT_(flowData->request->method != 0, "request method is NULL");
		ASSERT_(flowData->request->uri != 0, "request uri is NULL");
		ASSERT_(flowData->request->version != 0, "request version is NULL");

		ASSERT_(flowData->response->status != MESSAGE_END, "response must not end before request");
	} else {
		ASSERT_(flowData->response->status == MESSAGE_END, "message did not end");
		ASSERT_(!(flowData->response->status & MESSAGE_FLAG_FAILURE), "message end cannot be reached if a parsing error occurs");
		ASSERT_(flowData->response->entityTransfer!=TRANSFER_UNKNOWN, "transfer type unknown");
		ASSERT_(flowData->response->version != 0, "response version is NULL");
		ASSERT_(flowData->response->statusCode != 0, "response status code is NULL");
		ASSERT_(flowData->response->responsePhrase != 0, "response phrase is NULL");
	}
}
