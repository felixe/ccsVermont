/*
 * Vermont Aggregator Subsystem
 * Copyright (C) 2009 Vermont Project
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

#include "PacketHashtable.h"
#include <iostream>
#include <fstream>

#include "common/crc.hpp"

#include "common/ipfixlolib/ipfix.h"
#include "common/Misc.h"
#include "common/Time.h"
#include "HashtableBuckets.h"
#include "HttpAggregation.h"

using namespace InformationElement;

const uint32_t PacketHashtable::ExpHelperTable::UNUSED = 0xFFFFFFFF;
uint64_t processedPackets = 0;

PacketHashtable::PacketHashtable(Source<IpfixRecord*>* recordsource, Rule* rule,
		uint16_t minBufferTime, uint16_t maxBufferTime, uint8_t hashbits)
	: BaseHashtable(recordsource, rule, minBufferTime, maxBufferTime, hashbits),
	snapshotWritten(false), startTime(time(0))
{
	buildExpHelperTable();
	if (httpAggregation) {
		tcpmon = new TcpStreamMonitor(htableSize, tcpmonTimeoutOpened, tcpmonTimeoutClosed);
	}
}


PacketHashtable::~PacketHashtable()
{
	delete[] expHelperTable.keyFields;
	delete[] expHelperTable.aggFields;
	delete[] expHelperTable.revAggFields;
	delete[] expHelperTable.varSrcPtrFields;
	delete[] expHelperTable.revKeyFieldMapper;
	if (tcpmon)
	    delete tcpmon;
}

/**
 * copy functions which were extracted from ExpcopyData
 * those copy data from the original raw packet into the ipfix bucket in the hashtable
 * (always called, when a new bucket has to be created for a new flow)
 */
void PacketHashtable::copyDataEqualLengthNoMod(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	IpfixRecord::Data* dst = cfp->dst+efd->dstIndex;
	memcpy(dst, cfp->src, efd->srcLength);
}
void PacketHashtable::copyDataGreaterLengthIPNoMod(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	IpfixRecord::Data* dst = cfp->dst+efd->dstIndex;
	bzero(dst+efd->srcLength, efd->dstLength-efd->srcLength);
	memcpy(dst, cfp->src, efd->srcLength);
}
void PacketHashtable::copyDataGreaterLengthNoMod(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	IpfixRecord::Data* dst = cfp->dst+efd->dstIndex;
	bzero(dst, efd->dstLength-efd->srcLength);
	memcpy(dst+efd->dstLength-efd->srcLength, cfp->src, efd->srcLength);
}
void PacketHashtable::copyDataSetOne(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	IpfixRecord::Data* dst = cfp->dst+efd->dstIndex;
	memset(dst, 0, efd->dstLength);
	// set last byte of array to one (network byte order!)
	dst[efd->dstLength-1] = 1;
}
void PacketHashtable::copyDataSetZero(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	IpfixRecord::Data* dst = cfp->dst+efd->dstIndex;
	memset(dst, 0, efd->dstLength);
}
void PacketHashtable::copyDataFrontPayload(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	if (efd->typeSpecData.http.aggregate) {
		aggregateHttp(cfp->dst, *cfp->hbucket, reinterpret_cast<const Packet*>(cfp->src), efd, true, false);
	}
	else
		aggregateFrontPayload(cfp->dst, NULL, reinterpret_cast<const Packet*>(cfp->src), efd, true, false);
}
void PacketHashtable::copyDataFrontPayloadNoInit(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	if (efd->typeSpecData.http.aggregate) {
		aggregateHttp(cfp->dst, *cfp->hbucket, reinterpret_cast<const Packet*>(cfp->src), efd, true, true);
	}
	else
		aggregateFrontPayload(cfp->dst, NULL, reinterpret_cast<const Packet*>(cfp->src), efd, true, true);
}
void PacketHashtable::copyDataDummy(CopyFuncParameters* cfp)
{
}
void PacketHashtable::copyDataMaxPacketGap(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	memset(cfp->dst+efd->dstIndex, 0, efd->dstLength);
	memcpy(cfp->dst+efd->privDataOffset, cfp->src, 8);
}
void PacketHashtable::copyDataNanoseconds(CopyFuncParameters* cfp)
{
	ExpFieldData* efd = cfp->efd;
	uint64_t ntptime;
	ntptime = ntp64timegcc(*reinterpret_cast<const struct timeval*>(cfp->src));
	uint64_t ntp2 = htonll(ntptime);
	DPRINTFL(MSG_VDEBUG, "ntp2: %llu, ntptime/ntp2 %llX/%llX", ntp2, ntptime, ntp2);
	memcpy(cfp->dst+efd->dstIndex, &ntp2, sizeof(ntp2));
#ifdef DEBUG
	if (ntohll(*(uint64_t*)(cfp->dst+efd->dstIndex))<(1000000000ULL+(2208988800ULL<<32)) || ntohll(*(uint64_t*)(cfp->dst+efd->dstIndex))>(1300000000ULL+(2208988800ULL<<32))) {
		DPRINTFL(MSG_VDEBUG, "time before: %ds", reinterpret_cast<const struct timeval*>(cfp->src)->tv_sec);
		DPRINTFL(MSG_VDEBUG, "copy invalid end nano seconds: %lld s (%llX)", (ntohll(*(uint64_t*)(cfp->dst+efd->dstIndex))>>32)-2208988800U, *(uint64_t*)(cfp->dst+efd->dstIndex));
	}
#endif
}
void PacketHashtable::copyDataTransportOctets(CopyFuncParameters* cfp)
{
	const Packet* p = cfp->packet;
	uint16_t plen = p->pcapPacketLength-p->payloadOffset-p->layer2HeaderLen;
	if (p->payloadOffset==0 || p->payloadOffset==p->transportHeaderOffset) plen = 0;

	*reinterpret_cast<uint64_t*>(cfp->dst+cfp->efd->dstIndex) = htonll(plen);

	PayloadPrivateData* ppd;
	switch (cfp->packet->ipProtocolType) {
		case Packet::TCP:
			ppd = reinterpret_cast<PayloadPrivateData*>(cfp->dst+cfp->efd->privDataOffset);
			ppd->seq = ntohl(*reinterpret_cast<const uint32_t*>(p->data.netHeader+p->transportHeaderOffset+4))+plen+(p->data.netHeader[p->transportHeaderOffset+13] & 0x02 ? 1 : 0);
			ppd->initialized = true;
			DPRINTFL(MSG_VDEBUG, "%s=%lu, ppd->seq=%u", cfp->efd->typeId.toString().c_str(), ntohll(*reinterpret_cast<uint64_t*>(cfp->dst+cfp->efd->dstIndex)), ntohl(ppd->seq));
			break;

		default:
			break;
	}
}


/**
 * aggregates payload of packets to a certain maximum amount
 * only sequence number is regarded, succeeding packets with same sequence number
 * will overwrite data
 * ATTENTION: no stream reassembly is performed!
 */
void PacketHashtable::aggregateFrontPayload(IpfixRecord::Data* bucket, HashtableBucket* hbucket, const Packet* src,
		const ExpFieldData* efd, bool firstpacket, bool onlyinit)
{
	DPRINTFL(MSG_VDEBUG, "called (%s, %hhu, %hhu)", efd->typeId.toString().c_str(), firstpacket, onlyinit);
	PayloadPrivateData* ppd = reinterpret_cast<PayloadPrivateData*>(bucket+efd->privDataOffset);

	if (onlyinit) {
		ASSERT(firstpacket, "firstpacket must be set to 1 when onlyinit==1!");
		ppd->initialized = 0;  // set data struct to "non-initialized"
		return;
	}

	uint16_t plen = src->data_length-src->payloadOffset-src->layer2HeaderLen;
	if (src->payloadOffset==0 || src->payloadOffset==src->transportHeaderOffset) plen = 0;

	// DPA logic
	if (efd->typeSpecData.frontPayload.dpa && plen>0) {
		DpaPrivateData* dpd = reinterpret_cast<DpaPrivateData*>(bucket+efd->typeSpecData.frontPayload.dpaPrivDataOffset);
		bool revdir = efd->typeId.isReverseField();
		DPRINTFL(MSG_VDEBUG, "pkt revdir=%hhu, plen=%u, datarecv=%hhu, dpd=%u, buckdata=%X, dparevstartoffset=%u\n", revdir, plen, dpd->datarecv, dpd, bucket, efd->typeSpecData.frontPayload.dpaRevStartOffset);
		if (!dpd->datarecv) {
			// first time we receive data!
			dpd->revstart = revdir;
			if (efd->typeSpecData.frontPayload.dpaRevStartOffset != ExpHelperTable::UNUSED)
				*reinterpret_cast<uint8_t*>(bucket+efd->typeSpecData.frontPayload.dpaRevStartOffset) = revdir;
			dpd->datarecv = true;
			DPRINTFL(MSG_DEBUG, "1. revstart=%hhu\n", revdir);
		} else if ((revdir && !dpd->revstart) || (!revdir && dpd->revstart)) {
			// we are now in other direction
			dpd->revdata = true;
			DPRINTFL(MSG_DEBUG, "2. revdata=%hhu\n", dpd->revdata);
		} else if (dpd->revdata && ((dpd->revstart && revdir) || (!dpd->revstart && !revdir))) {
			// this flow *must* be exported!
			DPRINTFL(MSG_DEBUG, "3. export");
			if (efd->typeSpecData.frontPayload.dpaForcedExportOffset != ExpHelperTable::UNUSED)
				*reinterpret_cast<uint8_t*>(bucket+efd->typeSpecData.frontPayload.dpaForcedExportOffset) = 1;
			assert(hbucket!=NULL);
			hbucket->forceExpiry = true;
			return;
		} else {
			DPRINTFL(MSG_DEBUG, "4. okdata");
		}
	}

	IpfixRecord::Data* dst = bucket+efd->dstIndex;
	uint32_t seq = 0;
	if (src->ipProtocolType==Packet::TCP)
		seq = ntohl(*reinterpret_cast<const uint32_t*>(src->data.netHeader+src->transportHeaderOffset+4));
	DPRINTFL(MSG_VDEBUG, "seq:%u, len:%u, udp:%u", seq, ppd->byteCount, src->ipProtocolType==Packet::UDP);

	if (firstpacket || !ppd->initialized) {
		if (src->ipProtocolType==Packet::TCP && src->data.netHeader[src->transportHeaderOffset+13] & 0x02) {
			// SYN packet, so sequence number will be increased without any payload
			seq++;
		}
		// store sequence number and length of captured payload in private data
		ppd->seq = seq;
		ppd->byteCount = 0;
		ppd->initialized = 1;
	}

	// ignore packets that do either contain no payload or were not interpreted correctly
	if (plen>0) {
		uint32_t* pfplen = &ppd->byteCount;

		if (src->ipProtocolType==Packet::TCP) {
			uint32_t fseq = ppd->seq;
			uint32_t fpos = ppd->byteCount;

			DPRINTFL(MSG_VDEBUG, "plen:%u, fseq:%u, seq:%u, dstleng:%u", plen, fseq, seq, efd->dstLength);

			if (seq-fseq<efd->dstLength) {
				uint32_t pos = (seq!=0 ? seq-fseq : fpos);
				uint32_t len = efd->dstLength-pos;
				if (plen<len) len = plen;
				DPRINTFL(MSG_VDEBUG, "inserting payload data at %u with length %u", pos, len);
				memcpy(dst+pos, src->data.netHeader+src->payloadOffset, len);
				uint32_t maxpos = pos+len;
				if (*pfplen<maxpos) *pfplen = maxpos;

				// increase packet counter (if available)
				if (efd->typeSpecData.frontPayload.pktCountOffset != ExpHelperTable::UNUSED)
					(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.pktCountOffset))++;
				// copy current length to corresponding inforamtion element
				if (efd->typeSpecData.frontPayload.fpaLenOffset != ExpHelperTable::UNUSED)
					(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.fpaLenOffset)) = htonl(*pfplen);
			}
		} else if (src->ipProtocolType==Packet::UDP){
			uint32_t* pfplen = &ppd->byteCount;
			if (*pfplen<efd->dstLength) {
				uint32_t len = efd->dstLength-*pfplen;
				if (plen<len) len = plen;
				DPRINTFL(MSG_VDEBUG, "inserting payload data at %u with length %u", *pfplen, len);
				memcpy(dst+(*pfplen), src->data.netHeader+src->payloadOffset, len);
				*pfplen += len;

				// increase packet counter (if available)
				if (efd->typeSpecData.frontPayload.pktCountOffset != ExpHelperTable::UNUSED)
					(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.pktCountOffset))++;
				// copy current length to corresponding inforamtion element
				if (efd->typeSpecData.frontPayload.fpaLenOffset != ExpHelperTable::UNUSED)
					(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.fpaLenOffset)) = htonl(*pfplen);
			}
		}
	}

	DPRINTFL(MSG_VDEBUG, "new fplength: %u", *reinterpret_cast<uint32_t*>(bucket+efd->privDataOffset+4));
}

/**
 * aggregates payload of packets to a certain maximum amount
 * only sequence number is regarded, succeeding packets with same sequence number
 * will overwrite data
 * ATTENTION: no stream reassembly is performed!
 */
void PacketHashtable::aggregateHttp(IpfixRecord::Data* bucket, HashtableBucket* hbucket, const Packet* p,
		const ExpFieldData* efd, bool firstpacket, bool initialize)
{
	DPRINTFL(MSG_INFO, "aggregateHttp() of type: %s, firstpacket:%s, onlyinit:%s", efd->typeId.toString().c_str(), firstpacket ? "true" : "false", initialize ? "true" : "false");

	PayloadPrivateData* ppd = reinterpret_cast<PayloadPrivateData*>(bucket+efd->privDataOffset);
	FlowData* flowData = reinterpret_cast<FlowData*>(bucket+efd->typeSpecData.http.flowDataOffset);

	if (firstpacket) {
		ppd->byteCount = 0;
        // prepare pointer for http request method aggregation
        if (efd->typeSpecData.http.requestMethodOffset != ExpHelperTable::UNUSED)
            flowData->request.method = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.requestMethodOffset);

        // prepare pointer for http request uri aggregation
        if (efd->typeSpecData.http.requestUriOffset != ExpHelperTable::UNUSED) {
            flowData->request.uriLength = efd->typeSpecData.http.requestUriLength;
            flowData->request.uri = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.requestUriOffset);
        }

        // prepare pointer for http request version aggregation
        if (efd->typeSpecData.http.requestVersionOffset != ExpHelperTable::UNUSED)
            flowData->request.version = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.requestVersionOffset);

        // prepare pointer for http request host aggregation
         if (efd->typeSpecData.http.requestHostOffset != ExpHelperTable::UNUSED) {
             flowData->request.hostLength = efd->typeSpecData.http.requestHostLength;
             flowData->request.host = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.requestHostOffset);
         }

         // prepare pointer for http response version aggregation
         if (efd->typeSpecData.http.responseVersionOffset != ExpHelperTable::UNUSED)
             flowData->response.version = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.responseVersionOffset);

        // prepare pointer for http response code aggregation
        if (efd->typeSpecData.http.responseCodeOffset != ExpHelperTable::UNUSED)
            flowData->response.statusCode = reinterpret_cast<uint16_t*>(bucket+efd->typeSpecData.http.responseCodeOffset);

        // prepare pointer for http response phrase aggregation
        if (efd->typeSpecData.http.responsePhraseOffset != ExpHelperTable::UNUSED)
            flowData->response.responsePhrase = reinterpret_cast<char*>(bucket+efd->typeSpecData.http.responsePhraseOffset);
	}

	if (initialize) {
		ASSERT(firstpacket, "firstpacket must be set to 1 when onlyinit==1!");
		ppd->initialized = 0;
		return;
	}

	uint16_t payloadLength = p->net_total_length - p->payloadOffset;

	IpfixRecord::Data* dst = bucket+efd->dstIndex;

	const char* data = reinterpret_cast<const char*>(p->data.netHeader+p->payloadOffset);
	const char* dataEnd = data+payloadLength;

	const char* aggregationStart = 0;
	const char* aggregationEnd = 0;

	detectHttp(&data, &dataEnd, flowData, &aggregationStart, &aggregationEnd);

	if (!aggregationStart || !aggregationEnd || aggregationEnd <= aggregationStart) {
		DPRINTFL(MSG_INFO, "no payload has to be aggregated, skip packet payload");
		return;
	}

	uint32_t avail = efd->dstLength - ppd->byteCount;
	if (avail>0) {
		uint32_t size = aggregationEnd - aggregationStart;
		size = min(avail, size);
		memcpy(dst+ppd->byteCount, aggregationStart, size);
		ppd->byteCount+=size;
		DPRINTFL(MSG_INFO, "aggregated %u bytes of payload. %u bytes free.", size, efd->dstLength - ppd->byteCount);
		DPRINTFL(MSG_DEBUG, "payload aggregated = '%.*s'", size, aggregationStart);
	} else DPRINTFL(MSG_INFO, "not aggregating payload, no space left.");

	// increase packet counter (if available)
	if (efd->typeSpecData.frontPayload.pktCountOffset != ExpHelperTable::UNUSED)
		(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.pktCountOffset))++;
	// copy current length to corresponding information element
	if (efd->typeSpecData.frontPayload.fpaLenOffset != ExpHelperTable::UNUSED)
		(*reinterpret_cast<uint32_t*>(bucket+efd->typeSpecData.frontPayload.fpaLenOffset)) = htonl(ppd->byteCount);

	// TODO force expiry if the connection closes
	if (flowData->request.status == MESSAGE_END && flowData->response.status == MESSAGE_END) {
		DPRINTFL(MSG_INFO, "forcing expiry of http flow");
		hbucket->forceExpiry=true;
	} else if (flowData->response.status == MESSAGE_END && flowData->isResponse()){
	    uint8_t responseCount = *flowData->getFlowcount();
	    uint8_t requestCount = *flowData->getFlowcount(true);

	    if (responseCount>requestCount) {
	        DPRINTFL(MSG_INFO, "forcing expiry of http flow");
	        hbucket->forceExpiry=true;
	    }
	}

	http_type_t type = *flowData->getType();
	uint32_t* pipelinedOffsetEnd = 0;
	if (type == HTTP_TYPE_REQUEST && flowData->request.status == MESSAGE_END)
	    pipelinedOffsetEnd = &flowData->request.payloadOffsetEnd;
	if (type == HTTP_TYPE_RESPONSE && flowData->response.status == MESSAGE_END)
	        pipelinedOffsetEnd = &flowData->response.payloadOffsetEnd;

	if (pipelinedOffsetEnd && aggregationEnd < dataEnd) {
		// multiple requests are in this request, store the offset to the position and mark the request as pipelined
		uint16_t bufferOffset = 0;
		if (dataEnd-data > payloadLength)
			bufferOffset = (dataEnd-data) - payloadLength;
		*pipelinedOffsetEnd = (aggregationEnd - data) - bufferOffset;

		if (type == HTTP_TYPE_REQUEST) {
		    flowData->streamInfo->multipleRequests = true;
		}
		if (type == HTTP_TYPE_RESPONSE) {
		    flowData->streamInfo->multipleResponses = true;
		    // prevent expiry, since we need to access the bucket data when processing the pipelined respones
		    hbucket->forceExpiry=false;
		}
	}

	if (flowData->tempBuffer) {
	    free(flowData->tempBuffer);
	    flowData->tempBuffer = 0;
	}
}


/**
 * helper function for buildExpHelperTable
 * does some error checking on given parameters and returns function which is appropriate
 * to copy field in flow
 */
void (*PacketHashtable::getCopyDataFunction(const ExpFieldData* efd))(PacketHashtable::CopyFuncParameters*)
{
	// some error handling
	if (efd->modifier == Rule::Field::DISCARD) {
		THROWEXCEPTION("tried to copy data with field modifier set to discard");
	} else if ((efd->modifier != Rule::Field::KEEP) && (efd->modifier != Rule::Field::AGGREGATE) &&
			(efd->modifier < Rule::Field::MASK_START) && (efd->modifier > Rule::Field::MASK_END)) {
		THROWEXCEPTION("unknown modifier %d", efd->modifier);
	}
	switch (efd->typeId.enterprise) {
		case 0:
		case IPFIX_PEN_reverse:
			switch (efd->typeId.id) {
				case IPFIX_TYPEID_protocolIdentifier:
				case IPFIX_TYPEID_tcpControlBits:
				case IPFIX_TYPEID_classOfServiceIPv4:
					if (efd->dstLength != 1) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_TYPEID_sourceTransportPort:
				case IPFIX_TYPEID_destinationTransportPort:
				case IPFIX_TYPEID_icmpTypeCodeIPv4:
					if (efd->dstLength != 2) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_TYPEID_flowStartSysUpTime:
				case IPFIX_TYPEID_flowStartSeconds:
				case IPFIX_TYPEID_flowEndSysUpTime:
				case IPFIX_TYPEID_flowEndSeconds:
					if (efd->dstLength != 4) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_TYPEID_flowStartMilliSeconds:
				case IPFIX_TYPEID_flowStartMicroSeconds:
				case IPFIX_TYPEID_flowStartNanoSeconds:
				case IPFIX_TYPEID_flowEndMilliSeconds:
				case IPFIX_TYPEID_flowEndMicroSeconds:
				case IPFIX_TYPEID_flowEndNanoSeconds:
				case IPFIX_TYPEID_octetTotalCount:
				case IPFIX_TYPEID_octetDeltaCount:
				case IPFIX_TYPEID_packetDeltaCount:
				case IPFIX_TYPEID_packetTotalCount:
					if (efd->dstLength != 8) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_TYPEID_sourceIPv4Address:
				case IPFIX_TYPEID_destinationIPv4Address:
					if (efd->dstLength != 5) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_TYPEID_bgpSourceAsNumber:
				case IPFIX_TYPEID_bgpDestinationAsNumber:
					if (efd->dstLength != 2) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				default:
					THROWEXCEPTION("type unhandled by Packet Aggregator: %s", efd->typeId.toString().c_str());
					break;
			}
			break;

		case IPFIX_PEN_vermont:
		case IPFIX_PEN_vermont|IPFIX_PEN_reverse:
			switch (efd->typeId.id) {
				case IPFIX_ETYPEID_dpaForcedExport:
				case IPFIX_ETYPEID_dpaReverseStart:
					if (efd->dstLength != 1) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_ETYPEID_httpResponseCode:
				    if (efd->dstLength != 2) {
                        THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
                    }
                    break;

				case IPFIX_ETYPEID_frontPayloadLen:
				case IPFIX_ETYPEID_frontPayloadPktCount:
				case IPFIX_ETYPEID_maxPacketGap:
				case IPFIX_ETYPEID_dpaFlowCount:
					if (efd->dstLength != 4) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_ETYPEID_transportOctetDeltaCount:
					if (efd->dstLength != 8) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_ETYPEID_httpRequestVersion:
				case IPFIX_ETYPEID_httpResponseVersion:
                    if (efd->dstLength < 8) {
                        THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
                    }
                    break;

				case IPFIX_ETYPEID_frontPayload:
				case IPFIX_ETYPEID_httpRequestUri:
				case IPFIX_ETYPEID_httpRequestHost:
					if (efd->dstLength < 5) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_ETYPEID_httpRequestMethod:
					if (efd->dstLength < 16) {
						THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
					}
					break;

				case IPFIX_ETYPEID_httpResponsePhrase:
                    if (efd->dstLength < 16) {
                        THROWEXCEPTION("unsupported length %d for type %s", efd->dstLength, efd->typeId.toString().c_str());
                    }
                    break;
				default:
					THROWEXCEPTION("type unhandled by Packet Aggregator: %s", efd->typeId.toString().c_str());
					break;
			}
			break;

		default:
			THROWEXCEPTION("type unhandled by Packet Aggregator: %s", efd->typeId.toString().c_str());
			break;
	}

	// now decide on the correct copy function
	if (efd->typeId == IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont)) {
		return copyDataFrontPayload;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
		return copyDataFrontPayloadNoInit;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_frontPayloadLen, IPFIX_PEN_vermont)) {
		return copyDataDummy;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_transportOctetDeltaCount, IPFIX_PEN_vermont)) {
		return copyDataTransportOctets;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_maxPacketGap, IPFIX_PEN_vermont)) {
		return copyDataMaxPacketGap;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_frontPayloadPktCount, IPFIX_PEN_vermont) ||
			   efd->typeId == IeInfo(IPFIX_ETYPEID_dpaFlowCount, IPFIX_PEN_vermont) ||
			   efd->typeId == IeInfo(IPFIX_ETYPEID_dpaReverseStart, IPFIX_PEN_vermont) ||
			   efd->typeId == IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont)) {
		return copyDataDummy;
	} else if (efd->typeId == IeInfo(IPFIX_ETYPEID_httpRequestMethod, IPFIX_PEN_vermont) ||
			efd->typeId == IeInfo(IPFIX_ETYPEID_httpRequestUri, IPFIX_PEN_vermont) ||
			efd->typeId == IeInfo(IPFIX_ETYPEID_httpRequestVersion, IPFIX_PEN_vermont) ||
            efd->typeId == IeInfo(IPFIX_ETYPEID_httpResponseVersion, IPFIX_PEN_vermont) ||
            efd->typeId == IeInfo(IPFIX_ETYPEID_httpResponseCode, IPFIX_PEN_vermont) ||
            efd->typeId == IeInfo(IPFIX_ETYPEID_httpResponsePhrase, IPFIX_PEN_vermont) ||
            efd->typeId == IeInfo(IPFIX_ETYPEID_httpRequestHost, IPFIX_PEN_vermont)) {
		return copyDataDummy;
	}else if (efd->typeId == IeInfo(IPFIX_TYPEID_flowStartNanoSeconds, 0) ||
			efd->typeId == IeInfo(IPFIX_TYPEID_flowEndNanoSeconds, 0)) {
		return copyDataNanoseconds;
	} else if (efd->typeId.enterprise & IPFIX_PEN_reverse) {
		// ATTENTION: we treat all reverse elements the same: we set them to zero
		return copyDataSetZero;
	} else if (efd->dstLength == efd->srcLength) {
		return copyDataEqualLengthNoMod;
	} else if (efd->dstLength > efd->srcLength) {
		if (efd->typeId == IeInfo(IPFIX_TYPEID_sourceIPv4Address, 0) ||
				efd->typeId == IeInfo(IPFIX_TYPEID_destinationIPv4Address, 0)) {
			if ((efd->modifier >= Rule::Field::MASK_START) && (efd->modifier <= Rule::Field::MASK_END)) {
				if (efd->dstLength != 5 && efd->srcLength != 5) {
					THROWEXCEPTION("destination and source data size must be 5, but is %d/%d - mask needs to be stored in both of them", efd->dstLength, efd->srcLength);
				}
				return copyDataEqualLengthNoMod;
			} else {
				return copyDataGreaterLengthIPNoMod;
			}
		} else if (efd->typeId == IeInfo(IPFIX_TYPEID_packetDeltaCount, 0)) {
			return copyDataSetOne;
		} else if (efd->typeId == IeInfo(IPFIX_TYPEID_packetTotalCount, 0)) {
			return copyDataSetOne;
		} else {
			return copyDataGreaterLengthNoMod;
		}
	} else {
		THROWEXCEPTION("target buffer too small. Expected buffer %s of length %d", efd->typeId.toString().c_str(), efd->srcLength);
	}

	THROWEXCEPTION("this line should never be reached");
	return 0;
}

/**
 * @returns field length in bytes of corresponding entry in raw packet
 **/
uint16_t PacketHashtable::getRawPacketFieldLength(const IeInfo& type)
{
	if (type.enterprise == 0 || type.enterprise == IPFIX_PEN_reverse) {
		switch (type.id) {
			case IPFIX_TYPEID_protocolIdentifier:
			case IPFIX_TYPEID_tcpControlBits:
			case IPFIX_TYPEID_packetDeltaCount:
			case IPFIX_TYPEID_packetTotalCount:
			case IPFIX_TYPEID_classOfServiceIPv4:
				return 1;

			case IPFIX_TYPEID_icmpTypeCodeIPv4:
			case IPFIX_TYPEID_sourceTransportPort:
			case IPFIX_TYPEID_destinationTransportPort:
			case IPFIX_TYPEID_octetDeltaCount:
			case IPFIX_TYPEID_octetTotalCount:
				return 2;

			case IPFIX_TYPEID_flowStartSeconds:
			case IPFIX_TYPEID_flowEndSeconds:
			case IPFIX_TYPEID_sourceIPv4Address:
			case IPFIX_TYPEID_destinationIPv4Address:
				return 4;

			case IPFIX_TYPEID_flowStartMilliSeconds:
			case IPFIX_TYPEID_flowEndMilliSeconds:
			case IPFIX_TYPEID_flowStartNanoSeconds:
			case IPFIX_TYPEID_flowEndNanoSeconds:
				return 8;

			case IPFIX_TYPEID_bgpSourceAsNumber:
			case IPFIX_TYPEID_bgpDestinationAsNumber:
				return 0;

			default:
				THROWEXCEPTION("PacketHashtable: unknown typeid %s, failed to determine raw packet field length", type.toString().c_str());
				break;
		}
	} else if (type.enterprise == IPFIX_PEN_vermont || type.enterprise == (IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
		switch (type.id) {
			case IPFIX_ETYPEID_dpaForcedExport:
			case IPFIX_ETYPEID_dpaReverseStart:
				return 1;

			case IPFIX_ETYPEID_frontPayloadLen:
			case IPFIX_ETYPEID_maxPacketGap:
			case IPFIX_ETYPEID_frontPayloadPktCount:
			case IPFIX_ETYPEID_dpaFlowCount:
				return 4;

			case IPFIX_ETYPEID_transportOctetDeltaCount:
				return 8;

			case IPFIX_ETYPEID_frontPayload:
            case IPFIX_ETYPEID_httpRequestUri:
            case IPFIX_ETYPEID_httpRequestHost:
				return type.length;				// length is variable and is set in configuration

            case IPFIX_ETYPEID_httpRequestMethod:
            case IPFIX_ETYPEID_httpResponseCode:
            case IPFIX_ETYPEID_httpRequestVersion:
            case IPFIX_ETYPEID_httpResponseVersion:
            case IPFIX_ETYPEID_httpResponsePhrase:
                return 0;                       // length is variable, but this value should not matter

			default:
				THROWEXCEPTION("PacketHashtable: unknown typeid %s, failed to determine raw packet field length", type.toString().c_str());
				break;
		}

	}

	THROWEXCEPTION("PacketHashtable: unknown typeid %s, failed to determine raw packet field length", type.toString().c_str());
	return 0;
}


/**
 * Returns offset to the given standard Information Element Id in the raw packet (relative to packet's netheader)
 * @param id standard Information Element Id
 * @param p pointer to raw packet
 * @returns offset (in bytes) at which the data for the given field is located in the raw packet
 */
uint16_t PacketHashtable::getRawPacketFieldOffset(const IeInfo& type, const Packet* p)
{
	if (type.enterprise==0 || type.enterprise==IPFIX_PEN_reverse) {
		switch (type.id) {
			case IPFIX_TYPEID_packetTotalCount:
			case IPFIX_TYPEID_packetDeltaCount:
				return 10;
				break;

			case IPFIX_TYPEID_flowStartSeconds:
			case IPFIX_TYPEID_flowEndSeconds:
				return reinterpret_cast<const unsigned char*>(&p->time_sec_nbo) - p->data.netHeader;
				break;

			case IPFIX_TYPEID_flowStartMilliSeconds:
			case IPFIX_TYPEID_flowEndMilliSeconds:
				return reinterpret_cast<const unsigned char*>(&p->time_msec_nbo) - p->data.netHeader;
				break;

			case IPFIX_TYPEID_flowStartNanoSeconds:
			case IPFIX_TYPEID_flowEndNanoSeconds:
				return reinterpret_cast<const unsigned char*>(&p->timestamp) - p->data.netHeader;
				break;

			case IPFIX_TYPEID_octetDeltaCount:
			case IPFIX_TYPEID_octetTotalCount:
				return 2;
				break;

			case IPFIX_TYPEID_protocolIdentifier:
				return 9;
				break;

			case IPFIX_TYPEID_sourceIPv4Address:
				return 12;
				break;

			case IPFIX_TYPEID_destinationIPv4Address:
				return 16;
				break;
			case IPFIX_TYPEID_classOfServiceIPv4:
				return 1; 
				break; 

			case IPFIX_TYPEID_icmpTypeCodeIPv4:
				if(p->ipProtocolType == Packet::ICMP) {
					return p->transportHeader + 0 - p->data.netHeader;
				} else {
					DPRINTFL(MSG_VDEBUG, "given id is %s, protocol is %d, but expected was %d", type.toString().c_str(), p->ipProtocolType, Packet::ICMP);
				}
				break;
			case IPFIX_TYPEID_sourceTransportPort:
				if((p->ipProtocolType == Packet::TCP) || (p->ipProtocolType == Packet::UDP)) {
					return p->transportHeader + 0 - p->data.netHeader;
				} else {
					DPRINTFL(MSG_VDEBUG, "given id is %s, protocol is %d, but expected was %d or %d", type.toString().c_str(), p->ipProtocolType, Packet::UDP, Packet::TCP);
				}
				break;

			case IPFIX_TYPEID_destinationTransportPort:
				if((p->ipProtocolType == Packet::TCP) || (p->ipProtocolType == Packet::UDP)) {
					return p->transportHeader + 2 - p->data.netHeader;
				} else {
					DPRINTFL(MSG_VDEBUG, "given id is %s, protocol is %d, but expected was %d or %d", type.toString().c_str(), p->ipProtocolType, Packet::UDP, Packet::TCP);
				}
				break;

			case IPFIX_TYPEID_tcpControlBits:
				if(p->ipProtocolType == Packet::TCP) {
					return p->transportHeader + 13 - p->data.netHeader;
				} else {
					DPRINTFL(MSG_VDEBUG, "given id is %s, protocol is %d, but expected was %d", type.toString().c_str(), p->ipProtocolType, Packet::TCP);
				}
				break;
			default:
				THROWEXCEPTION("PacketHashtable: raw id offset into packet header for typeid %s is unkown, failed to determine raw packet offset", type.toString().c_str());
				break;
		}
	} else if (type.enterprise==IPFIX_PEN_vermont || type.enterprise==(IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
		switch (type.id) {
			case IPFIX_ETYPEID_maxPacketGap:
				return reinterpret_cast<const unsigned char*>(&p->time_msec_nbo) - p->data.netHeader;
				break;
			case IPFIX_ETYPEID_frontPayloadLen:
			case IPFIX_ETYPEID_frontPayloadPktCount:
			case IPFIX_ETYPEID_dpaForcedExport:
			case IPFIX_ETYPEID_dpaReverseStart:
				// all those fields aren't part of the raw packet header and are stored in the
				// typeSpecData.frontPayload field of IPFIX_ETYPEID_frontPayload.
				// so the offset to the zeroBytes pointer should be returned here
				break;
			case IPFIX_ETYPEID_dpaFlowCount:
				// this  field isn't part of the raw packet and is stored in the expHelperTable.
				// so the offset to the zeroBytes pointer should be returned here
				break;
			case IPFIX_ETYPEID_httpRequestMethod:
			case IPFIX_ETYPEID_httpRequestUri:
            case IPFIX_ETYPEID_httpRequestVersion:
            case IPFIX_ETYPEID_httpResponseVersion:
			case IPFIX_ETYPEID_httpResponseCode:
            case IPFIX_ETYPEID_httpResponsePhrase:
            case IPFIX_ETYPEID_httpRequestHost:
				// these fields do not have fixed positions in the raw packet
				break;
			default:

				THROWEXCEPTION("PacketHashtable: raw id offset into packet header for typeid %s is unkown, failed to determine raw packet offset", type.toString().c_str());
				break;
		}
	}
	// return just pointer to zero bytes as result
	return reinterpret_cast<const unsigned char*>(&p->zeroBytes) - p->data.netHeader;
}


/**
 * @returns if given field type is in varying positions inside a raw packet and inside the Packet structure
 */
bool PacketHashtable::isRawPacketPtrVariable(const IeInfo& type)
{
	switch (type.enterprise) {
		case 0:
		case IPFIX_PEN_reverse:
			switch (type.id) {
				case IPFIX_TYPEID_packetTotalCount:
				case IPFIX_TYPEID_packetDeltaCount:
				case IPFIX_TYPEID_flowStartSeconds:
				case IPFIX_TYPEID_flowEndSeconds:
				case IPFIX_TYPEID_flowStartMilliSeconds: // those elements are inside the Packet structure, not in the raw packet.
				case IPFIX_TYPEID_flowEndMilliSeconds:   // nevertheless, we may access it relative to the start of the packet data
				case IPFIX_TYPEID_flowStartNanoSeconds: //  ^
				case IPFIX_TYPEID_flowEndNanoSeconds:   //  ^
				case IPFIX_TYPEID_octetDeltaCount:
				case IPFIX_TYPEID_octetTotalCount:
				case IPFIX_TYPEID_protocolIdentifier:
				case IPFIX_TYPEID_sourceIPv4Address:
				case IPFIX_TYPEID_destinationIPv4Address:
				case IPFIX_TYPEID_classOfServiceIPv4:
				case IPFIX_TYPEID_bgpSourceAsNumber:
				case IPFIX_TYPEID_bgpDestinationAsNumber:
					return false;

				case IPFIX_TYPEID_icmpTypeCodeIPv4:
				case IPFIX_TYPEID_sourceTransportPort:
				case IPFIX_TYPEID_destinationTransportPort:
				case IPFIX_TYPEID_tcpControlBits:
					return true;
			}
			break;

		case IPFIX_PEN_vermont:
		case IPFIX_PEN_vermont|IPFIX_PEN_reverse:
			switch (type.id) {
				case IPFIX_ETYPEID_maxPacketGap:
				case IPFIX_ETYPEID_frontPayloadPktCount:
				case IPFIX_ETYPEID_dpaForcedExport:
				case IPFIX_ETYPEID_dpaFlowCount:
				case IPFIX_ETYPEID_dpaReverseStart:
	            case IPFIX_ETYPEID_httpRequestMethod:
	            case IPFIX_ETYPEID_httpRequestUri:
	            case IPFIX_ETYPEID_httpRequestVersion:
	            case IPFIX_ETYPEID_httpResponseVersion:
	            case IPFIX_ETYPEID_httpResponseCode:
	            case IPFIX_ETYPEID_httpResponsePhrase:
	            case IPFIX_ETYPEID_httpRequestHost:
					return false;

				case IPFIX_ETYPEID_frontPayload:
				case IPFIX_ETYPEID_frontPayloadLen:
				case IPFIX_ETYPEID_transportOctetDeltaCount:
					return true;
			}
			break;
	}


	THROWEXCEPTION("PacketHashtable: invalid type (%d), failed to determine variable state of field", type.id);
	return false;
}


/**
 * helper function for buildExpHelperTable
 */
void PacketHashtable::fillExpFieldData(ExpFieldData* efd, TemplateInfo::FieldInfo* hfi, Rule::Field::Modifier fieldModifier, uint16_t index)
{
	DPRINTFL(MSG_VDEBUG, "called for type id %s", hfi->type.toString().c_str());
	efd->typeId = hfi->type;
	efd->dstIndex = hfi->offset;
	efd->dstLength = hfi->type.length;
	efd->srcLength = getRawPacketFieldLength(hfi->type);
	efd->modifier = fieldModifier;
	efd->varSrcIdx = isRawPacketPtrVariable(hfi->type);
	efd->privDataOffset = hfi->privDataOffset;
	efd->typeSpecData.http.aggregate = false;
	efd->typeSpecData.http.flowDataOffset = ExpHelperTable::UNUSED;
	efd->typeSpecData.http.requestMethodOffset = ExpHelperTable::UNUSED;
	efd->typeSpecData.http.requestUriOffset = ExpHelperTable::UNUSED;
	efd->typeSpecData.http.requestUriLength = 0;
	efd->typeSpecData.http.responseCodeOffset = ExpHelperTable::UNUSED;

	// initialize static source index, if current field does not have a variable pointer
	if (!efd->varSrcIdx) {
		Packet p; // not good: create temporary packet just for initializing our optimization structure
		efd->srcIndex = getRawPacketFieldOffset(hfi->type, &p);
	}

	// special case for masked IPs: those contain variable pointers, if they are masked
	if ((efd->typeId==IeInfo(IPFIX_TYPEID_sourceIPv4Address, 0) || efd->typeId==IeInfo(IPFIX_TYPEID_destinationIPv4Address, 0)) &&
			(efd->modifier >= Rule::Field::MASK_START) && (efd->modifier <= Rule::Field::MASK_END)) {

		// ok, our dst/src ip has to be masked, so this is a variable pointer
		efd->varSrcIdx = true;
		// calculate inverse network mask using the modifier
		efd->data[4] = 32 - (efd->modifier - (int)Rule::Field::MASK_START);
		// save index of srcIndex, as this variable is overwritten by updatePointers for each packet
		efd->origSrcIndex = efd->srcIndex;

		if (efd->typeId.enterprise==0) {
			switch (efd->typeId.id) {
				case IPFIX_TYPEID_sourceIPv4Address:
					expHelperTable.srcIpEFieldIndex = index;
					break;
				case IPFIX_TYPEID_destinationIPv4Address:
					expHelperTable.dstIpEFieldIndex = index;
					break;
			}
		}

		// adjust srcLength, as our source length is 5 bytes including the appended mask!
		efd->srcLength = 5;
	}

	// set data efd field to the offset of IPFIX_ETYPEID_frontPayloadPktCount for front payload
	if (efd->typeId==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont)) {
		*reinterpret_cast<uint32_t*>(efd->data) = ExpHelperTable::UNUSED;
		for (int i=0; i<dataTemplate->fieldCount; i++) {
			TemplateInfo::FieldInfo* hfi = &dataTemplate->fieldInfo[i];
			if (hfi->type==IeInfo(IPFIX_ETYPEID_frontPayloadPktCount, IPFIX_PEN_vermont)) {
				*reinterpret_cast<uint32_t*>(efd->data) = hfi->offset;
			}
		}
	}

	// mark field as variable, if needed
	if (efd->varSrcIdx)	{
		DPRINTF("marking type id %s as variable source pointer", efd->typeId.toString().c_str());
		expHelperTable.varSrcPtrFields[expHelperTable.noVarSrcPtrFields++] = efd;
	}

	efd->copyDataFunc = getCopyDataFunction(efd);
}

/**
 * @returns if given field is available in a raw ip packet
 */
bool PacketHashtable::typeAvailable(const IeInfo& type)
{
	switch (type.enterprise) {
		case 0:
			switch (type.id) {
				case IPFIX_TYPEID_packetTotalCount:
				case IPFIX_TYPEID_packetDeltaCount:
				case IPFIX_TYPEID_flowStartSeconds:
				case IPFIX_TYPEID_flowEndSeconds:
				case IPFIX_TYPEID_flowStartMilliSeconds:
				case IPFIX_TYPEID_flowEndMilliSeconds:
				case IPFIX_TYPEID_flowStartNanoSeconds:
				case IPFIX_TYPEID_flowEndNanoSeconds:
				case IPFIX_TYPEID_octetTotalCount:
				case IPFIX_TYPEID_octetDeltaCount:
				case IPFIX_TYPEID_protocolIdentifier:
				case IPFIX_TYPEID_sourceIPv4Address:
				case IPFIX_TYPEID_destinationIPv4Address:
				case IPFIX_TYPEID_classOfServiceIPv4:
				case IPFIX_TYPEID_icmpTypeCodeIPv4:
				case IPFIX_TYPEID_sourceTransportPort:
				case IPFIX_TYPEID_destinationTransportPort:
				case IPFIX_TYPEID_tcpControlBits:
				case IPFIX_TYPEID_bgpSourceAsNumber:
				case IPFIX_TYPEID_bgpDestinationAsNumber:
					return true;
			}
			break;
		case IPFIX_PEN_vermont:
			switch (type.id) {
				case IPFIX_ETYPEID_frontPayloadLen:
				case IPFIX_ETYPEID_frontPayload:
				case IPFIX_ETYPEID_frontPayloadPktCount:
				case IPFIX_ETYPEID_maxPacketGap:
				case IPFIX_ETYPEID_dpaForcedExport:
				case IPFIX_ETYPEID_dpaFlowCount:
				case IPFIX_ETYPEID_dpaReverseStart:
				case IPFIX_ETYPEID_transportOctetDeltaCount:
	            case IPFIX_ETYPEID_httpRequestMethod:
	            case IPFIX_ETYPEID_httpRequestUri:
	            case IPFIX_ETYPEID_httpRequestVersion:
	            case IPFIX_ETYPEID_httpResponseVersion:
	            case IPFIX_ETYPEID_httpResponseCode:
	            case IPFIX_ETYPEID_httpResponsePhrase:
	            case IPFIX_ETYPEID_httpRequestHost:
					return true;
			}
			break;
	}

	return false;
}

/**
 * searches through all express structures and tries to find given information element
 * @returns offset of information element in destination template with start index at start of record data,
 *          returns ExpHelperTable::UNUSED if element was not found
 */
uint32_t PacketHashtable::getDstOffset(const IeInfo& ietype)
{
	uint32_t fcnt = 0;
	uint32_t offset = ExpHelperTable::UNUSED;
	for (vector<ExpFieldData*>::const_iterator iter=expHelperTable.allFields.begin(); iter!=expHelperTable.allFields.end(); iter++) {
		ExpFieldData* efd = *iter;
		if (efd->typeId==ietype) {
			fcnt++;
			offset = efd->dstIndex;
		}
	}
	if (fcnt>1) THROWEXCEPTION("Information element of type %s found more than once in template. This is not supported!", ietype.toString().c_str());
	return offset;
}


/**
 * builds internal structure expHelperTable for fast aggregation of raw packets
 * used in the express aggregator
 */
void PacketHashtable::buildExpHelperTable()
{
	expHelperTable.keyFields = new ExpFieldData[dataTemplate->fieldCount];
	expHelperTable.aggFields = new ExpFieldData[dataTemplate->fieldCount];
	expHelperTable.revAggFields = new ExpFieldData[dataTemplate->fieldCount];
	expHelperTable.varSrcPtrFields = new ExpFieldData *[dataTemplate->fieldCount];
	expHelperTable.revKeyFieldMapper = new ExpFieldData *[dataTemplate->fieldCount];
	expHelperTable.noVarSrcPtrFields = 0;
	expHelperTable.useDPA = false;


	struct OffsetData {
		uint32_t* ehtPointer;
		IeId ieid;
		IeEnterpriseNumber ieen;
	};

	vector<uint16_t> expkey2field; // maps entries from expHelperTable to original fields in template

	// TODO: fill with correct value!
	expHelperTable.dstIpEFieldIndex = false;
	expHelperTable.srcIpEFieldIndex = false;

	// at first, fill data structure with non-reversed aggregatable fields
	expHelperTable.noAggFields = 0;
	// special treatment of IPFIX_ETYPEID_frontPayload: for DPA, it must be the first element in the field
	// reason: it may cause forced export of data records
	for (int i=0; i<dataTemplate->fieldCount; i++) {
		TemplateInfo::FieldInfo* hfi = &dataTemplate->fieldInfo[i];
		if (hfi->type==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont)) {
			ExpFieldData* efd = &expHelperTable.aggFields[expHelperTable.noAggFields++];
			fillExpFieldData(efd, hfi, fieldModifier[i], expHelperTable.noAggFields-1);
		}
	}
	// now all other fields
	for (int i=0; i<dataTemplate->fieldCount; i++) {
		TemplateInfo::FieldInfo* hfi = &dataTemplate->fieldInfo[i];
		if (hfi->type.enterprise & IPFIX_PEN_reverse
				|| hfi->type==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont))
			continue;
		if (!typeAvailable(hfi->type)) {
			THROWEXCEPTION("Type %s is not contained in raw packet. Please remove it from PacketAggregator rule.", hfi->type.toString().c_str());
		}
		if (!isToBeAggregated(hfi->type)) continue;
		DPRINTF("including type %s.", hfi->type.toString().c_str());
		ExpFieldData* efd = &expHelperTable.aggFields[expHelperTable.noAggFields++];
		fillExpFieldData(efd, hfi, fieldModifier[i], expHelperTable.noAggFields-1);
		if (hfi->type==IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont)) {
			DPRINTFL(MSG_INFO, "activated dialog-based payload aggregation");
			expHelperTable.useDPA = true;
		}
	}
	DPRINTF("got %u aggregated fields", expHelperTable.noAggFields);

	// now the key fields
	expHelperTable.noKeyFields = 0;
	for (int i=0; i<dataTemplate->fieldCount; i++) {
		TemplateInfo::FieldInfo* hfi = &dataTemplate->fieldInfo[i];
		if (isToBeAggregated(hfi->type)) continue;
		ExpFieldData* efd = &expHelperTable.keyFields[expHelperTable.noKeyFields++];
		fillExpFieldData(efd, hfi, fieldModifier[i], expHelperTable.noKeyFields-1);
		expkey2field.push_back(i);
	}
	DPRINTF("got %u key fields", expHelperTable.noKeyFields);

	// reversed aggregatable fields
	expHelperTable.noRevAggFields = 0;
	// special treatment of IPFIX_ETYPEID_frontPayload: for DPA, it must be the first element in the field
	// reason: it may cause forced export of data records
	for (int i=0; i<dataTemplate->fieldCount; i++) {
		TemplateInfo::FieldInfo* hfi = &dataTemplate->fieldInfo[i];
		if (hfi->type==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
			ExpFieldData* efd = &expHelperTable.revAggFields[expHelperTable.noRevAggFields++];
			fillExpFieldData(efd, hfi, fieldModifier[i], expHelperTable.noRevAggFields-1);
		}
	}
	// now the other fields
	for (int i=0; i<dataTemplate->fieldCount; i++) {
		TemplateInfo::FieldInfo hfi = dataTemplate->fieldInfo[i];
		if ((hfi.type.enterprise & IPFIX_PEN_reverse) == 0
				|| hfi.type==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse))
			continue;
		hfi.type.enterprise &= ~IPFIX_PEN_reverse;
		if (!typeAvailable(hfi.type)) {
			THROWEXCEPTION("Type %s is not contained in raw packet. Please remove it from PacketAggregator rule.", hfi.type.toString().c_str());
		}
		if (!isToBeAggregated(hfi.type)) continue;
		ExpFieldData* efd = &expHelperTable.revAggFields[expHelperTable.noRevAggFields++];
		fillExpFieldData(efd, &dataTemplate->fieldInfo[i], fieldModifier[i], expHelperTable.noRevAggFields-1);
		hfi.type.enterprise |= IPFIX_PEN_reverse;
	}
	DPRINTF("got %u reverse aggregated fields", expHelperTable.noRevAggFields);

	// build helper structure for mapping key fields to their reversed elements
	if (biflowAggregation) {
		for (uint32_t i=0; i<expHelperTable.noKeyFields; i++) {
			uint32_t fid = revKeyMapper[expkey2field[i]];
			vector<uint16_t>::iterator fit = find(expkey2field.begin(), expkey2field.end(), fid);
			if (fit==expkey2field.end()) THROWEXCEPTION("Error when calculating biflow table. This should not happen. (DOH!)");
			expHelperTable.revKeyFieldMapper[i] = &expHelperTable.keyFields[fit-expkey2field.begin()];
			DPRINTF("mapping key exph id %hu to id %hu\n", fit-expkey2field.begin(), i);
		}
	}
	DPRINTF("got %u fields with variable source pointers", expHelperTable.noVarSrcPtrFields);

	// insert all fields in one array for fast processing
	for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
		expHelperTable.allFields.push_back(&expHelperTable.aggFields[i]);
	}
	for (uint32_t i=0; i<expHelperTable.noRevAggFields; i++) {
		expHelperTable.allFields.push_back(&expHelperTable.revAggFields[i]);
	}
	for (uint32_t i=0; i<expHelperTable.noKeyFields; i++) {
		expHelperTable.allFields.push_back(&expHelperTable.keyFields[i]);
	}
	expHelperTable.dpaFlowCountOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_dpaFlowCount, IPFIX_PEN_vermont));

	uint32_t flowDataOffset = 0;
	if (httpAggregation) {
	    // add space for the FlowData structure at the end of the private data
	    flowDataOffset=fieldLength + privDataLength;
		privDataLength += sizeof(FlowData);
	}

	// search for offsets of fields that are linked with each other
	IeInfo ieinfo;
	ieinfo.enterprise = 0;
	for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
		ExpFieldData* efd = &expHelperTable.aggFields[i];
		if (efd->typeId==IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont)) {
			efd->typeSpecData.frontPayload.fpaLenOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_frontPayloadLen, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.pktCountOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_frontPayloadPktCount, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.dpaForcedExportOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.dpaRevStartOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_dpaReverseStart, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.dpa = expHelperTable.useDPA;

			efd->typeSpecData.http.flowDataOffset = flowDataOffset; // both directions share the same FlowData information
			efd->typeSpecData.http.aggregate = httpAggregation;
            efd->typeSpecData.http.requestVersionOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestVersion, IPFIX_PEN_vermont));
			efd->typeSpecData.http.requestMethodOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestMethod, IPFIX_PEN_vermont));
			efd->typeSpecData.http.requestUriOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestUri, IPFIX_PEN_vermont));
			efd->typeSpecData.http.requestHostOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestHost, IPFIX_PEN_vermont));
			efd->typeSpecData.http.responseVersionOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponseVersion, IPFIX_PEN_vermont));
			efd->typeSpecData.http.responseCodeOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponseCode, IPFIX_PEN_vermont));
			efd->typeSpecData.http.responsePhraseOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponsePhrase, IPFIX_PEN_vermont));

			efd->typeSpecData.frontPayload.dpaPrivDataOffset = ExpHelperTable::UNUSED;
			if (expHelperTable.useDPA) {
				for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
					ExpFieldData* efd2 = &expHelperTable.aggFields[i];
					if (efd2->typeId==IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont)) {
						efd->typeSpecData.frontPayload.dpaPrivDataOffset = efd2->privDataOffset;
						break;
					}
				}
			}

            if (efd->typeSpecData.http.requestUriOffset != ExpHelperTable::UNUSED) {
                for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
                    ExpFieldData* efd2 = &expHelperTable.aggFields[i];
                    if (efd2->typeId==IeInfo(IPFIX_ETYPEID_httpRequestUri, IPFIX_PEN_vermont)) {
                        efd->typeSpecData.http.requestUriLength = efd2->dstLength;
                        break;
                    }
                }
            }

            if (efd->typeSpecData.http.requestHostOffset != ExpHelperTable::UNUSED) {
                for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
                    ExpFieldData* efd2 = &expHelperTable.aggFields[i];
                    if (efd2->typeId==IeInfo(IPFIX_ETYPEID_httpRequestHost, IPFIX_PEN_vermont)) {
                        efd->typeSpecData.http.requestHostLength = efd2->dstLength;
                        break;
                    }
                }
            }
		}
	}
	for (uint32_t i=0; i<expHelperTable.noRevAggFields; i++) {
		ExpFieldData* efd = &expHelperTable.revAggFields[i];
		if (efd->typeId == IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
			efd->typeSpecData.frontPayload.fpaLenOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_frontPayloadLen, IPFIX_PEN_vermont|IPFIX_PEN_reverse));
			efd->typeSpecData.frontPayload.pktCountOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_frontPayloadPktCount, IPFIX_PEN_vermont|IPFIX_PEN_reverse));
			efd->typeSpecData.frontPayload.dpaForcedExportOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.dpaRevStartOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_dpaReverseStart, IPFIX_PEN_vermont));
			efd->typeSpecData.frontPayload.dpa = expHelperTable.useDPA;

            efd->typeSpecData.http.flowDataOffset = flowDataOffset; // both directions share the same FlowData information
            efd->typeSpecData.http.aggregate = httpAggregation;
            efd->typeSpecData.http.requestVersionOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestVersion, IPFIX_PEN_vermont));
            efd->typeSpecData.http.requestMethodOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestMethod, IPFIX_PEN_vermont));
            efd->typeSpecData.http.requestUriOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestUri, IPFIX_PEN_vermont));
            efd->typeSpecData.http.requestHostOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpRequestHost, IPFIX_PEN_vermont));
            efd->typeSpecData.http.responseVersionOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponseVersion, IPFIX_PEN_vermont));
            efd->typeSpecData.http.responseCodeOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponseCode, IPFIX_PEN_vermont));
            efd->typeSpecData.http.responsePhraseOffset = getDstOffset(IeInfo(IPFIX_ETYPEID_httpResponsePhrase, IPFIX_PEN_vermont));

			efd->typeSpecData.frontPayload.dpaPrivDataOffset = ExpHelperTable::UNUSED;
			if (expHelperTable.useDPA) {
				for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
					ExpFieldData* efd2 = &expHelperTable.aggFields[i];
					if (efd2->typeId==IeInfo(IPFIX_ETYPEID_dpaForcedExport, IPFIX_PEN_vermont)) {
						efd->typeSpecData.frontPayload.dpaPrivDataOffset = efd2->privDataOffset;
						break;
					}
				}
			}

            if (efd->typeSpecData.http.requestUriOffset != ExpHelperTable::UNUSED) {
                for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
                    ExpFieldData* efd2 = &expHelperTable.aggFields[i];
                    if (efd2->typeId==IeInfo(IPFIX_ETYPEID_httpRequestUri, IPFIX_PEN_vermont)) {
                        efd->typeSpecData.http.requestUriLength = efd2->dstLength;
                        break;
                    }
                }
            }

            if (efd->typeSpecData.http.requestHostOffset != ExpHelperTable::UNUSED) {
                for (uint32_t i=0; i<expHelperTable.noAggFields; i++) {
                    ExpFieldData* efd2 = &expHelperTable.aggFields[i];
                    if (efd2->typeId==IeInfo(IPFIX_ETYPEID_httpRequestHost, IPFIX_PEN_vermont)) {
                        efd->typeSpecData.http.requestHostLength = efd2->dstLength;
                        break;
                    }
                }
            }
		}
	}
}



/**
 * calculates hash for given raw packet data in express aggregator
 */
uint32_t PacketHashtable::calculateHash(const IpfixRecord::Data* data, TcpStream* ts)
{
	uint32_t hash = 0xAAAAAAAA;
	for (int i=0; i<expHelperTable.noKeyFields; i++) {
		ExpFieldData* efd = &expHelperTable.keyFields[i];
		DPRINTFL(MSG_VDEBUG, "hash for i=%u, typeid=%s, srcpointer=%X", i, efd->typeId.toString().c_str(),
				efd->srcLength, reinterpret_cast<const char*>(data)+efd->srcIndex);
		hash = crc32(hash, efd->srcLength, reinterpret_cast<const char*>(data)+efd->srcIndex);
	}
    if (ts) {
        hash = crc32(hash, sizeof(uint32_t), &ts->streamNum);
        uint8_t flows = ts->isForward() ? ts->httpData->forwardFlows : ts->httpData->reverseFlows;
        if (flows > 0)
            hash = crc32(hash, sizeof(uint8_t), &flows);
    }
	DPRINTFL(MSG_INFO, "buckets hash =    %8u", hash & (htableSize-1));
	return hash & (htableSize-1);
}

/**
 * calculates hash for given raw packet data in express aggregator for reverse flows
 */
uint32_t PacketHashtable::calculateHashRev(const IpfixRecord::Data* data, TcpStream* ts)
{
	uint32_t hash = 0xAAAAAAAA;
	for (int i=0; i<expHelperTable.noKeyFields; i++) {
		ExpFieldData* efd = expHelperTable.revKeyFieldMapper[i];
		DPRINTFL(MSG_VDEBUG, "hashrev for i=%u, typeid=%s, length=%u, srcpointer=%X", i,
				efd->typeId.toString().c_str(), efd->srcLength, reinterpret_cast<const char*>(data)+efd->srcIndex);
		hash = crc32(hash, efd->srcLength, reinterpret_cast<const char*>(data)+efd->srcIndex);
	}
    if (ts) {
        hash = crc32(hash, sizeof(uint32_t), &ts->streamNum);
        uint8_t flows = ts->isForward() ? ts->httpData->forwardFlows : ts->httpData->reverseFlows;
        if (flows > 0)
            hash = crc32(hash, sizeof(uint8_t), &flows);
    }
	DPRINTFL(MSG_INFO, "buckets revhash = %8u", hash & (htableSize-1));
	return hash & (htableSize-1);
}

/**
 * copies data from raw packet to a bucket which will be inserted into the hashtable
 * for aggregation (part of express aggregator)
 */
boost::shared_array<IpfixRecord::Data> PacketHashtable::buildBucketData(Packet* p, HttpStreamData* streamData, HashtableBucket** hbucket)
{
    DPRINTFL(MSG_DEBUG, "building bucket data");
	// new field for insertion into hashtable
	boost::shared_array<IpfixRecord::Data> htdata(new IpfixRecord::Data[fieldLength+privDataLength]);
	IpfixRecord::Data* data = htdata.get();
	bzero(data, fieldLength+privDataLength);
	CopyFuncParameters cfp;

	cfp.dst = data;
	cfp.packet = p;
	cfp.hbucket = hbucket;

	bool flowDataInitialized = false;

	// copy all data ...
	for (vector<ExpFieldData*>::const_iterator iter=expHelperTable.allFields.begin(); iter!=expHelperTable.allFields.end(); iter++) {
		ExpFieldData* efd = *iter;
		
		if (efd->typeSpecData.http.aggregate && !flowDataInitialized) {
			DPRINTFL(MSG_INFO, "initializing flow data");
			initializeFlowData(reinterpret_cast<FlowData*> (data+efd->typeSpecData.http.flowDataOffset), streamData);
			flowDataInitialized = true;
		}

		cfp.src = reinterpret_cast<IpfixRecord::Data*>(p->data.netHeader)+efd->srcIndex;
		cfp.efd = efd;
		efd->copyDataFunc(&cfp);
	}
	return htdata;
}

/**
 * This functions copies data from an existing bucket to a new memory area. The reason for this is
 * that when http aggregation is performed and a packet with multiple http requests arrives we need
 * to create a flow for each request, i.e. one bucket for each request. Those buckets mainly share
 * the same information. But data like FlowData has to be reset and the right payload offset has to
 * be set. The
 * @param srcData Source data from a bucket
 * @param streamData Pointer to the proper HttpStreamData
 * @param srcFlowData Source flow information. Used to calculate payload offset
 * @return Returns the newly created copy of the
 */
boost::shared_array<IpfixRecord::Data> PacketHashtable::createBucketDataCopy(const IpfixRecord::Data* srcData, HttpStreamData* streamData, FlowData* srcFlowData)
{
    DPRINTFL(MSG_DEBUG, "copying bucket data");
	// new field for insertion into hashtable
	boost::shared_array<IpfixRecord::Data> htdata(new IpfixRecord::Data[fieldLength+privDataLength]);
	IpfixRecord::Data* data = htdata.get();
	memcpy(data, srcData, fieldLength); // copy all the normal aggregation fields (also http related fields are copied, but we erase them below)
	bzero(data+fieldLength, privDataLength); // reset private data fields

	// initialize flowdata
	for (vector<ExpFieldData*>::const_iterator iter=expHelperTable.allFields.begin(); iter!=expHelperTable.allFields.end(); iter++) {
		ExpFieldData* efd = *iter;
		if (efd->typeSpecData.http.aggregate) {
		    ExpFieldData::TypeSpecificData::HttpAggregationData& http = efd->typeSpecData.http;
		    DPRINTFL(MSG_INFO, "initializing flow data");
			FlowData* flowData = reinterpret_cast<FlowData*> (data + http.flowDataOffset);
			initializeFlowData(flowData, streamData);

			// a TCP segment can contain multiple HTTP messages. each of these HTTP messages is processed separately. this offset
			// specifies the position, in the current TCP segment payload, at which the last HTTP message ended or rather the position
			// the new HTTP message starts
			if (streamData->multipleRequests)
			    flowData->request.payloadOffset = srcFlowData->request.payloadOffsetEnd;
			else
			    flowData->response.payloadOffset = srcFlowData->response.payloadOffsetEnd;

			// erase all HTTP related fields
			if (http.requestMethodOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.requestMethodOffset, IPFIX_ELENGTH_httpRequestMethod);
			if (http.requestUriOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.requestUriOffset, http.requestUriLength);
			if (http.requestVersionOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.requestVersionOffset, IPFIX_ELENGTH_httpVersionIdentifier);
			if (http.requestHostOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.requestHostOffset, http.requestHostLength);

			if (http.responseVersionOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.responseVersionOffset, IPFIX_ELENGTH_httpVersionIdentifier);
			if (http.responseCodeOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.responseCodeOffset, IPFIX_ELENGTH_httpResponseCode);
			if (http.responseVersionOffset != ExpHelperTable::UNUSED)
			    bzero(data + http.responseVersionOffset, IPFIX_ELENGTH_httpResponsePhrase);
			break;
		}
	}

	for (vector<ExpFieldData*>::const_iterator iter=expHelperTable.allFields.begin(); iter!=expHelperTable.allFields.end(); iter++) {
	    ExpFieldData* efd = *iter;
	    // erase front-payload and reverse front-payload
        if (efd->typeId.id == IPFIX_ETYPEID_frontPayload && (efd->typeId.enterprise & IPFIX_PEN_vermont)) {
            bzero(data + efd->dstIndex, efd->dstLength);
        }
	}

	return htdata;
}

/**
 * aggregates the given field of the raw packet data into a hashtable bucket
 * (part of express aggregator)
 */
void PacketHashtable::aggregateField(const ExpFieldData* efd, HashtableBucket* hbucket,
		const IpfixRecord::Data* deltaData, IpfixRecord::Data* data)
{
	IpfixRecord::Data* baseData = data+efd->dstIndex;
	int64_t gap;

	uint64_t ntptime;
	uint64_t ntp2;
	PayloadPrivateData* ppd;
	const Packet* p;
	uint16_t plen;

	if (efd->typeId.id==IPFIX_ETYPEID_transportOctetDeltaCount && (efd->typeId.enterprise&IPFIX_PEN_vermont)) {
		p = reinterpret_cast<const Packet*>(deltaData);
		plen = p->pcapPacketLength-p->payloadOffset-p->layer2HeaderLen;

		if ((p->ipProtocolType==Packet::TCP || p->ipProtocolType==Packet::UDP) &&
			p->payloadOffset>0 && p->payloadOffset!=p->transportHeaderOffset && plen>0) {
			uint64_t seq;
			switch (p->ipProtocolType) {
				case Packet::TCP:
					ppd = reinterpret_cast<PayloadPrivateData*>(data+efd->privDataOffset);
					seq = ntohl(*reinterpret_cast<const uint32_t*>(p->data.netHeader+p->transportHeaderOffset+4));

					if (!ppd->initialized) {
						ppd->seq = ntohl(*reinterpret_cast<const uint32_t*>(p->data.netHeader+p->transportHeaderOffset+4))+plen+(p->data.netHeader[p->transportHeaderOffset+13] & 0x02 ? 1 : 0);

						*reinterpret_cast<uint64_t*>(baseData) = htonll(plen);
						ppd->initialized = true;
						break;
					}

					if (seq+plen>ppd->seq && seq+plen<ppd->seq+HT_MAX_TCP_WINDOW_SIZE) {
						*reinterpret_cast<uint64_t*>(baseData) = htonll(seq-ppd->seq+plen+ntohll(*reinterpret_cast<uint64_t*>(baseData)));
						 ppd->seq = seq+plen;
					} else if (0x100000000LL+seq+plen>ppd->seq && 0x100000000LL+seq+plen<ppd->seq+HT_MAX_TCP_WINDOW_SIZE) { // wrap-around
						*reinterpret_cast<uint64_t*>(baseData) = htonll(0x100000000LL+seq-ppd->seq+plen+ntohll(*reinterpret_cast<uint64_t*>(baseData)));
						 ppd->seq = seq+plen;
					}
					DPRINTFL(MSG_VDEBUG, "%s=%llu, ppd->seq=%u", efd->typeId.toString().c_str(), ntohll(*reinterpret_cast<uint64_t*>(baseData)), ntohl(ppd->seq));
					break;

				case Packet::UDP:
					DPRINTF("blub udp");
					*reinterpret_cast<uint64_t*>(baseData) = htonll(plen+ntohll(*reinterpret_cast<uint64_t*>(baseData)));
					break;

				default:
					DPRINTF("blub default");
					break;
			}
		}
	} else {
		switch (efd->typeId.enterprise) {
			case 0:
				switch (efd->typeId.id) {
					case IPFIX_TYPEID_flowStartSeconds:
						*(uint32_t*)baseData = lesserUint32Nbo(*(uint32_t*)baseData, *(uint32_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowStartMilliSeconds:
						*(uint64_t*)baseData = lesserUint64Nbo(*(uint64_t*)baseData, *(uint64_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowStartNanoSeconds:
						ntptime = ntp64timegcc(*reinterpret_cast<const struct timeval*>(deltaData));
						ntp2 = htonll(ntptime);
						DPRINTFL(MSG_VDEBUG, "base: %lu s, delta: %lu s", (ntohll(*(uint64_t*)baseData)>>32)-2208988800U, ntohll(ntp2));
						DPRINTFL(MSG_VDEBUG, "base: %llX , delta: %llX", ntohll(*(uint64_t*)baseData), ntohll(ntp2));
						*(uint64_t*)baseData = lesserUint64Nbo(*(uint64_t*)baseData, ntp2);
			#ifdef DEBUG
						if (ntohll(*(uint64_t*)baseData)<(1000000000ULL+(2208988800ULL<<32)) || ntohll(*(uint64_t*)baseData)>(1300000000ULL+(2208988800ULL<<32))) {
							DPRINTFL(MSG_VDEBUG, "invalid start nano seconds: %lu s", (ntohll(*(uint64_t*)baseData)>>32)-2208988800U);
							DPRINTFL(MSG_VDEBUG, "base: %llX , delta: %llX", *(uint64_t*)baseData, *(uint64_t*)deltaData);
						}
			#endif
						break;

					case IPFIX_TYPEID_flowEndSeconds:
						*(uint32_t*)baseData = greaterUint32Nbo(*(uint32_t*)baseData, *(uint32_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowEndMilliSeconds:
						*(uint64_t*)baseData = greaterUint64Nbo(*(uint64_t*)baseData, *(uint64_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowEndNanoSeconds:
						ntptime = ntp64timegcc(*reinterpret_cast<const struct timeval*>(deltaData));
						ntp2 = htonll(ntptime);
						*(uint64_t*)baseData = greaterUint64Nbo(*(uint64_t*)baseData, ntp2);
			#ifdef DEBUG
						if (ntohll(*(uint64_t*)baseData)<(1000000000ULL+(2208988800ULL<<32)) || ntohll(*(uint64_t*)baseData)>(1300000000ULL+(2208988800ULL<<32)))
							DPRINTFL(MSG_VDEBUG, "invalid end nano seconds: %lu s", (ntohll(*(uint64_t*)baseData)>>32)-2208988800U);
			#endif
						break;

					case IPFIX_TYPEID_octetTotalCount: // 8 byte dst, 2 byte src
					case IPFIX_TYPEID_octetDeltaCount: // 8 byte dst, 2 byte src
						*(uint64_t*)baseData = htonll(ntohll(*(uint64_t*)baseData) + ntohs(*(uint16_t*)deltaData));
						break;

					case IPFIX_TYPEID_packetTotalCount: // 8 byte dst, no src
					case IPFIX_TYPEID_packetDeltaCount: // 8 byte dst, no src
						*(uint64_t*)baseData = htonll(ntohll(*(uint64_t*)baseData)+1);
						break;

					case IPFIX_TYPEID_tcpControlBits:  // 1 byte src and dst, bitwise-or flows
						*(uint8_t*)baseData |= *(uint8_t*)deltaData;
						break;

						// no other types needed, as this is only for raw field input
					default:
						DPRINTF("non-aggregatable type: %s", efd->typeId.toString().c_str());
						break;
				}
				break;

			case IPFIX_PEN_reverse:
				switch (efd->typeId.id) {
					case IPFIX_TYPEID_flowStartSeconds:
						if (*(uint32_t*)baseData==0)
							*(uint32_t*)baseData = *(uint32_t*)deltaData;
						else
							*(uint32_t*)baseData = lesserUint32Nbo(*(uint32_t*)baseData, *(uint32_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowStartMilliSeconds:
						if (*(uint64_t*)baseData==0)
							*(uint64_t*)baseData = *(uint64_t*)deltaData;
						else
							*(uint64_t*)baseData = lesserUint64Nbo(*(uint64_t*)baseData, *(uint64_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowStartNanoSeconds:
						if (*(uint64_t*)baseData==0)
							*(uint64_t*)baseData = *(uint64_t*)deltaData;
						else {
							ntptime = ntp64timegcc(*reinterpret_cast<const struct timeval*>(deltaData));
							ntp2 = htonll(ntptime);
							*(uint64_t*)baseData = lesserUint64Nbo(*(uint64_t*)baseData, ntp2);
						}
						break;

					case IPFIX_TYPEID_flowEndSeconds:
						*(uint32_t*)baseData = greaterUint32Nbo(*(uint32_t*)baseData, *(uint32_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowEndMilliSeconds:
						*(uint64_t*)baseData = greaterUint64Nbo(*(uint64_t*)baseData, *(uint64_t*)deltaData);
						break;

					case IPFIX_TYPEID_flowEndNanoSeconds:
						ntptime = ntp64timegcc(*reinterpret_cast<const struct timeval*>(deltaData));
						ntp2 = htonll(ntptime);
						*(uint64_t*)baseData = greaterUint64Nbo(*(uint64_t*)baseData, ntp2);
			#ifdef DEBUG
						if (ntohll(*(uint64_t*)baseData)<(1000000000ULL+(2208988800ULL<<32)) || ntohll(*(uint64_t*)baseData)>(1300000000ULL+(2208988800ULL<<32)))
							DPRINTFL(MSG_VDEBUG, "invalid end nano seconds: %lu s", (ntohll(*(uint64_t*)baseData)>>32)-2208988800U);
			#endif
						break;

					case IPFIX_TYPEID_octetTotalCount: // 8 byte dst, 2 byte src
					case IPFIX_TYPEID_octetDeltaCount: // 8 byte dst, 2 byte src
						*(uint64_t*)baseData = htonll(ntohll(*(uint64_t*)baseData) + ntohs(*(uint16_t*)deltaData));
						break;

					case IPFIX_TYPEID_packetTotalCount: // 8 byte dst, no src
					case IPFIX_TYPEID_packetDeltaCount: // 8 byte dst, no src
						*(uint64_t*)baseData = htonll(ntohll(*(uint64_t*)baseData)+1);
						break;

					case IPFIX_TYPEID_tcpControlBits: // 1 byte src and dst, bitwise-or flows
						*(uint8_t*)baseData |= *(uint8_t*)deltaData;
						break;

					default:
						DPRINTF("non-aggregatable type: %s", efd->typeId.toString().c_str());
						break;
				}
				break;

			case IPFIX_PEN_vermont:
				switch (efd->typeId.id) {
					case IPFIX_ETYPEID_frontPayload:
						if (httpAggregation)
							aggregateHttp(data, hbucket, reinterpret_cast<const Packet*>(deltaData), efd, false, false);
						else
							aggregateFrontPayload(data, hbucket, reinterpret_cast<const Packet*>(deltaData), efd, false, false);
						break;

					case IPFIX_ETYPEID_maxPacketGap:
						gap = (int64_t)ntohll(*(int64_t*)deltaData)-(int64_t)ntohll(*reinterpret_cast<const uint64_t*>(data+efd->privDataOffset));
						if (gap<0) gap = -gap;
						DPRINTFL(MSG_VDEBUG, "gap: %u, oldgap: %u", gap, ntohl(*(uint32_t*)baseData));

						if ((uint32_t)gap > ntohl(*(uint32_t*)baseData)) *(uint32_t*)baseData = htonl(gap);
						*reinterpret_cast<uint64_t*>(data+efd->privDataOffset) = *(uint64_t*)deltaData;
						break;

	                case IPFIX_ETYPEID_httpRequestMethod:
	                case IPFIX_ETYPEID_httpRequestUri:
	                case IPFIX_ETYPEID_httpRequestVersion:
	                case IPFIX_ETYPEID_httpResponseVersion:
	                case IPFIX_ETYPEID_httpResponseCode:
	                case IPFIX_ETYPEID_httpResponsePhrase:
	                case IPFIX_ETYPEID_httpRequestHost:
					case IPFIX_ETYPEID_frontPayloadLen:
						// ignore these fields, as FPA aggregation does everything needed
						break;

					default:
						DPRINTF("non-aggregatable type: %s", efd->typeId.toString().c_str());
						break;
				}
				break;

			case IPFIX_PEN_vermont|IPFIX_PEN_reverse:
				switch (efd->typeId.id) {
					case IPFIX_ETYPEID_frontPayload:
						if (httpAggregation)
							aggregateHttp(data, hbucket, reinterpret_cast<const Packet*>(deltaData), efd, false, false);
						else
							aggregateFrontPayload(data, hbucket, reinterpret_cast<const Packet*>(deltaData), efd, false, false);
						break;

					case IPFIX_ETYPEID_maxPacketGap:
						gap = (int64_t)ntohll(*(int64_t*)deltaData)-(int64_t)ntohll(*reinterpret_cast<const uint64_t*>(data+efd->privDataOffset));
						if (gap<0) gap = -gap;
						DPRINTFL(MSG_VDEBUG, "gap: %u, oldgap: %u", gap, ntohl(*(uint32_t*)baseData));

						if ((uint32_t)gap > ntohl(*(uint32_t*)baseData)) *(uint32_t*)baseData = htonl(gap);
						*reinterpret_cast<uint64_t*>(data+efd->privDataOffset) = *(uint64_t*)deltaData;
						break;

	                case IPFIX_ETYPEID_httpRequestMethod:
	                case IPFIX_ETYPEID_httpRequestUri:
	                case IPFIX_ETYPEID_httpRequestVersion:
	                case IPFIX_ETYPEID_httpResponseVersion:
	                case IPFIX_ETYPEID_httpResponseCode:
	                case IPFIX_ETYPEID_httpResponsePhrase:
	                case IPFIX_ETYPEID_httpRequestHost:
					case IPFIX_ETYPEID_frontPayloadLen:
						// ignore these fields, as FPA aggregation does everything needed
						break;

					default:
						DPRINTF("non-aggregatable type: %s", efd->typeId.toString().c_str());
						break;
				}
				break;
			default:
				DPRINTF("non-aggregatable type: %s", efd->typeId.toString().c_str());
				break;
		}
	}
}

/**
 * aggregates the given raw packet data into the hashtable bucket
 */
void PacketHashtable::aggregateFlow(HashtableBucket* bucket, const Packet* p, bool reverse)
{
	IpfixRecord::Data* data = bucket->data.get();
	if (!reverse) {
		for (int i=0; i<expHelperTable.noAggFields && !bucket->forceExpiry; i++) {
			ExpFieldData* efd = &expHelperTable.aggFields[i];
			aggregateField(efd, bucket, p->data.netHeader+efd->srcIndex, data);
		}
	} else {
		for (int i=0; i<expHelperTable.noRevAggFields && !bucket->forceExpiry; i++) {
			ExpFieldData* efd = &expHelperTable.revAggFields[i];
			aggregateField(efd, bucket, p->data.netHeader+efd->srcIndex, data);
		}
	}
	// TODO: tobi_optimize
	// replace call of time() with access to a static variable which is updated regularly (such as every 100ms)
	if (!bucket->forceExpiry) {
		bucket->expireTime = time(0) + minBufferTime;

		if (bucket->forceExpireTime>bucket->expireTime) {
			exportList.remove(bucket->listNode);
			exportList.push(bucket->listNode);
		}
	}
}

/**
 * compares if given hashtable bucket data is equal with raw packet data
 * @returns true if equal, false if not equal
 */
bool PacketHashtable::equalFlow(IpfixRecord::Data* bucket, const Packet* p)
{
	for (int i=0; i<expHelperTable.noKeyFields; i++) {
		ExpFieldData* efd = &expHelperTable.keyFields[i];
		DPRINTFL(MSG_VDEBUG, "equal for i=%u, typeid=%s, length=%u, srcpointer=%X", i, efd->typeId.toString().c_str(), efd->srcLength, p->data.netHeader+efd->srcIndex);
		// just compare srcLength bytes, as we still have our original packet data
		if (memcmp(bucket+efd->dstIndex, p->data.netHeader+efd->srcIndex, efd->srcLength)!=0) {
		    DPRINTFL(MSG_DEBUG, "equalFlow = false");
			return false;
		}
	}
	DPRINTFL(MSG_DEBUG, "equalFlow = true");
	return true;
}

/**
 * compares if given hashtable bucket data is equal with raw packet data, reverse version
 * (for biflow aggregation)
 * @returns true if equal, false if not equal
 */
bool PacketHashtable::equalFlowRev(IpfixRecord::Data* bucket, const Packet* p)
{
	for (int i=0; i<expHelperTable.noKeyFields; i++) {
		ExpFieldData* efdsrc = &expHelperTable.keyFields[i];
		ExpFieldData* efddst = expHelperTable.revKeyFieldMapper[i];

		DPRINTFL(MSG_VDEBUG, "equalrev for i=%u, typeid=%s, length=%u, srcpointer=%X", i, efdsrc->typeId.toString().c_str(), efdsrc->srcLength, p->data.netHeader+efdsrc->srcIndex);
		// just compare srcLength bytes, as we still have our original packet data
		if (memcmp(bucket+efddst->dstIndex, p->data.netHeader+efdsrc->srcIndex, efdsrc->srcLength)!=0) {
		    DPRINTFL(MSG_DEBUG, "equalFlowRev = false");
			return false;
		}
	}
	DPRINTFL(MSG_DEBUG, "equalFlowRev = true");
	return true;
}


/**
 * masks ip addresses inside raw packet and creates a mask field
 * (part of express aggregator)
 */
void PacketHashtable::createMaskedField(IpfixRecord::Data* address, uint8_t imask)
{
	DPRINTF("unmasked address: %08X", *reinterpret_cast<uint32_t*>(address));
	if (imask > 0) {
		if (imask == 8) {
			address[3] = 0x00;
		} else if (imask == 16) {
			address[2] = 0x00;
			address[3] = 0x00;
		} else if (imask == 24) {
			address[1] = 0x00;
			address[2] = 0x00;
			address[3] = 0x00;
		} else if (imask == 32) {
			address[0] = 0x00;
			address[1] = 0x00;
			address[2] = 0x00;
			address[3] = 0x00;
		} else {
			// tobi_optimize: do this mask calculation during initialization phase of express aggregator
			int pattern = 0;
			int i;
			for(i = 0; i < imask; i++) {
				pattern |= (1 << i);
			}
			*(uint32_t*)address = htonl(ntohl(*(uint32_t*)(address)) & ~pattern);
		}
	}
	DPRINTF("masked address: %08X", *reinterpret_cast<uint32_t*>(address));
}


/**
 * masks ip addresses if desired in ExpFieldData->[0-3]
 * additional mask information (is 5th byte in aggregated data) is in ExpFieldData->data[4]
 */
void PacketHashtable::createMaskedFields(Packet* p)
{
	if (expHelperTable.dstIpEFieldIndex > 0) {
		ExpFieldData* efd = &expHelperTable.keyFields[expHelperTable.dstIpEFieldIndex];
		// copy *original* ip address in *raw packet* to our temporary structure
		*reinterpret_cast<uint32_t*>(&efd->data[0]) = *reinterpret_cast<uint32_t*>(p->data.netHeader+efd->origSrcIndex);
		// then mask it
		createMaskedField(&efd->data[0], efd->data[4]);
	}
	if (expHelperTable.srcIpEFieldIndex > 0) {
		ExpFieldData* efd = &expHelperTable.keyFields[expHelperTable.srcIpEFieldIndex];
		// copy *original* ip address in *raw packet* to our temporary structure
		*reinterpret_cast<uint32_t*>(&efd->data[0]) = *reinterpret_cast<uint32_t*>(p->data.netHeader+efd->origSrcIndex);
		// then mask it
		createMaskedField(&efd->data[0], efd->data[4]);
	}
}

/**
 * updates variable pointers to the raw packet data for each packet
 * (part of express aggregator)
 */
void PacketHashtable::updatePointers(const Packet* p)
{
	for (int i=0; i<expHelperTable.noVarSrcPtrFields; i++) {
		ExpFieldData* efd = expHelperTable.varSrcPtrFields[i];

		bool dodefault = true;
		if (efd->typeId.enterprise==0 &&
				(efd->typeId.id==IPFIX_TYPEID_destinationIPv4Address || efd->typeId.id==IPFIX_TYPEID_sourceIPv4Address)) {
			// perform a hack for masked IPs:
			// IP addresses which are to be masked are copied to efd->data[0-3] and masked there
			// now we need to do some pointer arithmetic to be able to access those transparently afterwards
			// note: only IP types to be masked have efd->varSrcIdx set
			efd->srcIndex = reinterpret_cast<uintptr_t>(&efd->data[0])-reinterpret_cast<uintptr_t>(p->data.netHeader);
			dodefault = false;
		} else if ((efd->typeId.enterprise&IPFIX_PEN_vermont)) {
			switch (efd->typeId.id) {
				// aggregation and copy functions for frontPayload need to have source pointer
				// pointing to packet structure
				case IPFIX_ETYPEID_frontPayload:
				case IPFIX_ETYPEID_transportOctetDeltaCount:
					efd->srcIndex = reinterpret_cast<uintptr_t>(p)-reinterpret_cast<uintptr_t>(p->data.netHeader);
					dodefault = false;
				break;
			}
		}
		if (dodefault) {
			// standard procedure for transport header fields
			efd->srcIndex = getRawPacketFieldOffset(efd->typeId, p);
		}
	}
}

void PacketHashtable::updateBucketData(HashtableBucket* bucket)
{
	statTotalEntries++;
	BucketListElement* node = hbucketIM.getNewInstance();
	node->reset();
	node->bucket = bucket;
	bucket->listNode = node;
	exportList.push(node);
}

/**
 * inserts the given raw packet into the hashtable
 * ATTENTION:
 *  - this function expects not to be called in parallel, as it uses internal buffers which are
 *    *NOT* thread-safe
 *  - hashes are calculated based on raw packet (masks are already applied then)
 */
void PacketHashtable::aggregatePacket(Packet* p)
{
	// the following lock should almost never block (only during reconfiguration)
	while (atomic_lock(&aggInProgress)) {
		timespec req;
		req.tv_sec = 0;
		req.tv_nsec = 50000000;
		nanosleep(&req, &req);
	}

    uint32_t slen = p->net_total_length - p->payloadOffset; // TCP segment length

	DPRINTFL(MSG_DEBUG, "new packet #%lu| frame.len: %u, ip.len = %u, tcp.len = %u, captured bytes = %d",
	        ++processedPackets, p->pcapPacketLength, p->net_total_length, slen, p->data_length);

#ifdef DEBUG
	int32_t refCount = p->getReferenceCount();
	if (refCount != 1)
	    THROWEXCEPTION("wrong reference count: %d. expected: 1", refCount);
#endif

    TcpStream* tcpStream =  0;
    if (httpAggregation){
        p->addReference();
        tcpStream = tcpmon->dissect(p);
        if (!tcpStream) {
            DPRINTFL(MSG_INFO, "packet is out of order. skipping packet!");
            atomic_release(&aggInProgress);
            return;
        }
#ifdef DEBUG
        if (!tcpStream->httpData)
            THROWEXCEPTION("stream data is null");
        if (!tcpStream->httpData->direction)
            THROWEXCEPTION("stream data was not initialized properly");
#endif
    }

    bool first = true;
    while (p) {
        // captured TCP segment length must be >0
        if (httpAggregation && slen <= 0) {
            DPRINTFL(MSG_INFO, "captured payload for packet is 0 bytes. skipping packet!");
            p->removeReference();
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if ((refCount != 1 && first) || (refCount != 0 && !first))
        THROWEXCEPTION("wrong reference count: %d. expected: %d", refCount, first ? 1 : 0);
#endif
            atomic_release(&aggInProgress);
            return;
        }

        DPRINTF("PacketHashtable::aggregatePacket()");
        updatePointers(p);
        createMaskedFields(p);

        bool createAfterExpiry = true;
        IpfixRecord::Data* tsrcData = 0;

        HttpStreamData* httpData = NULL;

        if (httpAggregation) {
            httpData = tcpStream->httpData;
            DPRINTFL(MSG_INFO, "forward flows %u", httpData->forwardFlows);
            DPRINTFL(MSG_INFO,"reverse flows %u", httpData->reverseFlows);
        }

        uint32_t hash = calculateHash(p->data.netHeader, tcpStream);
        DPRINTFL(MSG_INFO, "packet hash=%u", hash);

        // search bucket inside hashtable
        HashtableBucket* bucket = buckets[hash];

        uint32_t* oldflowcount = NULL;
        bool flowfound = false;
        bool expiryforced = false;
        if (bucket != 0) {
            DPRINTFL(MSG_INFO, "bucket found for hash!");
            // This slot is already used, search spill chain for equal flow
            while (1) {
                if (equalFlow(bucket->data.get(), p)) {
                    DPRINTF("aggregate flow in normal direction");
                    tsrcData = bucket->data.get();
                    aggregateFlow(bucket, p, 0);
                    if (!bucket->forceExpiry) {
                        flowfound = true;
                    } else {
                        DPRINTFL(MSG_VDEBUG, "forced expiry of bucket");
                        removeBucket(bucket);
                        expiryforced = true;
                        if (expHelperTable.dpaFlowCountOffset != ExpHelperTable::UNUSED)
                            oldflowcount = reinterpret_cast<uint32_t*>(bucket->data.get()+expHelperTable.dpaFlowCountOffset);
                        bucket = NULL;
                        if (httpAggregation) {
                            createAfterExpiry = false;
                        }
                    }
                    break;
                }

                if (bucket->next==NULL) {
                    break;
                }
                bucket = (HashtableBucket*)bucket->next;
            }
        } else DPRINTFL(MSG_INFO,"no bucket found for hash!");
        if (biflowAggregation && !flowfound && !expiryforced) {
            // search for reverse direction
            uint32_t rhash = calculateHashRev(p->data.netHeader, tcpStream);
            DPRINTFL(MSG_VDEBUG, "rev packet hash=%u", rhash);
            bucket = buckets[rhash];
            if (bucket != 0) DPRINTFL(MSG_INFO, "revbucket found for hash!");
            else DPRINTFL(MSG_INFO, "no revbucket found for hash!");
            while (bucket!=0) {
                if (equalFlowRev(bucket->data.get(), p)) {
                    DPRINTF("aggregate flow in reverse direction");
                    tsrcData = bucket->data.get();
                    aggregateFlow(bucket, p, 1);
                    if (!bucket->forceExpiry) {
                        flowfound = true;
                    } else {
                        DPRINTFL(MSG_VDEBUG, "forced expiry of bucket");
                        removeBucket(bucket);
                        expiryforced = true;
                        if (expHelperTable.dpaFlowCountOffset != ExpHelperTable::UNUSED)
                            oldflowcount = reinterpret_cast<uint32_t*>(bucket->data.get()+expHelperTable.dpaFlowCountOffset);
                        bucket = NULL;
                        if (httpAggregation) {
                            createAfterExpiry = false;
                        }
                    }
                    break;
                }
                bucket = (HashtableBucket*)bucket->next;
            }
        }

        if (createAfterExpiry && (!flowfound || expiryforced)) {
            // create new flow
            DPRINTFL(MSG_INFO, "creating new bucket for hash: %u", hash);

            HashtableBucket* firstbucket = buckets[hash];
            if (httpAggregation) {
                boost::shared_array<IpfixRecord::Data> htdata; // just a temporary stopgap
                buckets[hash] = createBucket(htdata, p->observationDomainID, firstbucket, 0, hash);
                buckets[hash]->data = buildBucketData(p, httpData, &buckets[hash]);
                tsrcData = buckets[hash]->data.get();
            }
            else
                buckets[hash] = createBucket(buildBucketData(p), p->observationDomainID, firstbucket, 0, hash);
            if (firstbucket) {
                firstbucket->prev = buckets[hash];
                statMultiEntries++;
            } else {
                statEmptyBuckets--;
            }
            buckets[hash]->inTable = true;
            if (oldflowcount) {
                DPRINTFL(MSG_VDEBUG, "oldflowcount: %u", ntohl(*oldflowcount));
                *reinterpret_cast<uint32_t*>(buckets[hash]->data.get()+expHelperTable.dpaFlowCountOffset) = htonl(ntohl(*oldflowcount)+1);
            }
            updateBucketData(buckets[hash]);
        }

        if (httpAggregation) {
            if ((httpData->multipleRequests || httpData->multipleResponses))
                processMultipleHttpMessages(tsrcData, httpData, p, tcpStream);
            p->removeReference();
#ifdef DEBUG
    int32_t refCount = p->getReferenceCount();
    if ((refCount != 1 && first) || (refCount != 0 && !first))
        THROWEXCEPTION("wrong reference count: %d. expected: %d", refCount, first ? 1 : 0);
#endif
            p = tcpmon->nextPacketForStream(tcpStream);
            if (p) {
                // update slen
                slen = p->net_total_length - p->payloadOffset; // TCP segment length
            }
        } else {
            break;
        }
        first = false;
    }

    if (tcpmon) {
        tcpmon->expireStreams();
#ifdef DEBUG
    tcpmon->printStreamCount();
#endif
    }
	//if (!snapshotWritten && (time(0)- 300 > starttime)) writeHashtable();
	// FIXME: enable snapshots again by configuration
	atomic_release(&aggInProgress);
}

/**
 * Processes subsequent HTTP messages contained in a single Packet.
 * A TCP segment can contain payload of different also multiple HTTP messages. If TCP segment
 * payload was not parsed completely, this method processes the remaining TCP segment payload.
 * Every HTTP messages discovered is put in a separate flow. If no flow exists yet a new one
 * is created.
 * @param srcData Source data, of the flow in which the initial part of the TCP segment payload was aggregated
 * @param streamData TCP stream related HTTP data
 * @param p The Packet whose TCP payload should be processed
 * @param tcpStream TCP stream related to the Packet
 */
void PacketHashtable::processMultipleHttpMessages(IpfixRecord::Data* srcData,  HttpStreamData* streamData, Packet* p, TcpStream* tcpStream) {
    if (streamData->multipleRequests && streamData->multipleResponses)
        THROWEXCEPTION("error occurred, packet cannot contain multiple requests and responses at the same time");

    // the packet we are currently processing contains at least one more http message or part of it.
    // so we might have to create a new flow for the next message in the payload if no flow exists yet.

    http_type_t type = tcpStream->isForward() ? tcpStream->httpData->forwardType : tcpStream->httpData->reverseType;

    if (type == HTTP_TYPE_UNKNOWN)
        THROWEXCEPTION("HTTP type was set faulty");

    if (type == HTTP_TYPE_RESPONSE) {
        uint8_t* requestCount = 0;
        uint8_t* responseCount = 0;

        if ((tcpStream->isForward() && tcpStream->httpData->forwardType == HTTP_TYPE_REQUEST) ||
                (tcpStream->isReverse() && tcpStream->httpData->reverseType == HTTP_TYPE_RESPONSE)) {
            requestCount = &tcpStream->httpData->forwardFlows;
            responseCount = &tcpStream->httpData->reverseFlows;
        } else {
            requestCount = &tcpStream->httpData->reverseFlows;
            responseCount = &tcpStream->httpData->forwardFlows;
        }

        if (requestCount >= responseCount)
            aggregateIntoExistingFlow(srcData, streamData, p, tcpStream);
    }

    if (streamData->multipleRequests || streamData->multipleResponses)
        aggregateIntoNewFlow(srcData, streamData, p, tcpStream);
}

/**
 * Aggregates subsequent HTTP messages contained in a single Packet into existing flows.
 * A TCP segment can contain payload of multiple different HTTP messages. If the payload of a
 * TCP segment was not parsed completely, this method processes the remaining payload.
 * Every HTTP message discovered is aggregated into a separate flow.
 * If no flow exists for a Packet, the method returns.
 * @param srcData Source data, of the flow in which the initial part of the TCP segment payload was aggregated
 * @param streamData TCP stream related HTTP data
 * @param p The Packet whose TCP payload should be processed
 * @param tcpStream TCP stream related to the Packet
 */
void PacketHashtable::aggregateIntoExistingFlow(IpfixRecord::Data* srcData,  HttpStreamData* streamData, Packet* p, TcpStream* tcpStream) {
    ExpFieldData* efd = 0;
    for (int i=0;i<expHelperTable.noRevAggFields;i++) {
        ExpFieldData* tefd = &expHelperTable.revAggFields[i];
        if (tefd->typeSpecData.http.aggregate) {
            efd = tefd;
            break;
        }
    }
    if (!efd)
        THROWEXCEPTION("could not find the right ExpFieldData");

    while (streamData->multipleResponses) {
        DPRINTFL(MSG_VDEBUG, "the payload of the segment was not parsed completely, look for another http response");
        // get the FlowData from the flow in which previous part of the TCP segment payload was aggregated
        FlowData* srcFlowData = reinterpret_cast<FlowData*>(srcData+efd->typeSpecData.http.flowDataOffset);

        // search for reverse direction
         uint32_t rhash = calculateHashRev(p->data.netHeader, tcpStream);

         bool found = false;
         HashtableBucket* bucket = buckets[rhash];
         if (bucket != 0) DPRINTFL(MSG_INFO, "revbucket found for hash!");
         else DPRINTFL(MSG_INFO, "no revbucket found for hash!");
         while (bucket!=0) {
             if (equalFlowRev(bucket->data.get(), p)) {
                 found = true;
                 DPRINTF("aggregate flow in reverse direction");
                 srcData = bucket->data.get();
                 break;
             }
             bucket = (HashtableBucket*)bucket->next;
         }

         if (!found) {
             // no flow was found, we have to create one
             msg(MSG_ERROR, "could not find a reverse flow for a HTTP response.");
             return;
         }

         // if a flow is found we can aggregate into the flow
         FlowData* dstFlowData = reinterpret_cast<FlowData*>(srcData+efd->typeSpecData.http.flowDataOffset);
         dstFlowData->response.payloadOffsetEnd = srcFlowData->response.payloadOffsetEnd;
         // reset the status
         streamData->multipleResponses = false;
         aggregateHttp(srcData, bucket, p, efd, false, false);

         // expire the bucket if needed
         if (bucket->forceExpiry) {
             DPRINTFL(MSG_VDEBUG, "forced expiry of bucket");
             removeBucket(bucket);
         }
    }
}

/**
 * Aggregates subsequent HTTP messages contained in a single Packet into distinct flows.
 * A TCP segment can contain payload of multiple different HTTP messages. If the payload of a
 * TCP segment was not parsed completely, this method processes the remaining payload.
 * Every HTTP message discovered is aggregated into a separate flow.
 * @param srcData Source data, of the flow in which the initial part of the TCP segment payload was aggregated
 * @param streamData TCP stream related HTTP data
 * @param p The Packet whose TCP payload should be processed
 * @param tcpStream TCP stream related to the Packet
 */
void PacketHashtable::aggregateIntoNewFlow(IpfixRecord::Data* srcData,  HttpStreamData* streamData, Packet* p, TcpStream* tcpStream) {
    ExpFieldData* efd = 0;
    for (int i=0;i<expHelperTable.noAggFields;i++) {
        ExpFieldData* tefd = &expHelperTable.aggFields[i];
        if (tefd->typeSpecData.http.aggregate) {
            efd = tefd;
            break;
        }
    }
    if (!efd)
        THROWEXCEPTION("could not find the right ExpFieldData");

    while (streamData->multipleRequests || streamData->multipleResponses) {
        DPRINTFL(MSG_VDEBUG, "the payload of the segment was not parsed completely, look for another http %s", streamData->multipleRequests ? "request" : "response");
        // get the FlowData from the flow in which previous part of the TCP segment payload was aggregated
        FlowData* srcFlowData = reinterpret_cast<FlowData*>(srcData+efd->typeSpecData.http.flowDataOffset);

        // we need to create a new bucket/flow for the next HTTP message
        uint32_t hash = calculateHash(p->data.netHeader, tcpStream);
        HashtableBucket* firstbucket = buckets[hash];

        // create a copy of the bucket from previous flow
        boost::shared_array<IpfixRecord::Data> htdata = createBucketDataCopy(srcData, streamData, srcFlowData);
        // create the new bucket
        buckets[hash] = createBucket(htdata, p->observationDomainID, firstbucket, 0, hash);

        // reset the status and start restart the HTTP aggregation for the remaining part of the payload
        // if the payload still contains more then one HTTP message, this status will be reset to true
        streamData->multipleRequests = false;
        streamData->multipleResponses = false;

        aggregateHttp(htdata.get(), buckets[hash], p, efd, true, false);

        // statistics...
        if (firstbucket) {
            firstbucket->prev = buckets[hash];
            statMultiEntries++;
        } else {
            statEmptyBuckets--;
        }

        // update bucket
        buckets[hash]->inTable = true;
        updateBucketData(buckets[hash]);
        srcData = htdata.get();

        // expire the bucket if needed
        if (buckets[hash]->forceExpiry) {
            DPRINTFL(MSG_VDEBUG, "forced expiry of bucket");
            removeBucket(buckets[hash]);
        }
    }
}

void PacketHashtable::snapshotHashtable()
{
	// FIXME: this snapshotting code is not good ...
	int count = 0;
	ofstream fout("/home/sistmika/vermont/dos-attack/hashtable.txt");
	if (fout){

		fout << "bucket\tnumber\n";
		for(uint32_t i = 0; i < htableSize; i++){
			HashtableBucket* bucket = buckets[i];
			if (bucket == 0) count = 0;
			else{
				count++;
				while(bucket->next != 0){
					count++;
					bucket = (HashtableBucket*)bucket->next;
					}
			}
			fout << i+1 << "\t" << count  << "\n";
			count =0;
		}
		fout.close();
		snapshotWritten = true;
	}
	else {
	DPRINTF("unable to open file to write Hashtable\n");
	}
}

