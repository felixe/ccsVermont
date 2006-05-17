/** @file
 * IPFIX Collector module.
 *
 * The IPFIX Collector module receives messages from lower levels (see @c processMessage())
 * and parses the message into separate Templates, Options and Flows. It then
 * invokes the appropriate callback routine for each Template, Option and Flow received
 * (see the @c setTemplateCallback() and @c setDataRecordCallback() function groups).
 *
 * The Collector module supports higher-level modules by providing field types and offsets along 
 * with the raw data block of individual messages passed via the callback functions (see @c TemplateInfo)
 *
 */

/******************************************************************************

IPFIX Collector module
Copyright (C) 2004 Christoph Sommer
http://www.deltadevelopment.de/users/christoph/ipfix

FIXME: Basic support for NetflowV9 packets, templates and flow records
is provided. Will break when fed field types with type ID >= 0x8000.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

******************************************************************************/

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

/* for ntohll et al */
#include "ipfixlolib/ipfixlolib.h"

#include "rcvIpfix.h"
#include "templateBuffer.h"
#include "ipfix.h"

#include "msg.h"
/***** Defines ************************************************************/

#define SUPPORT_NETFLOWV9

/***** Constants ************************************************************/

#define NetflowV9_SetId_Template  0

#define MAX_MSG_LEN	65536

/***** Macros ************************************************************/

#define byte uint8_t

/***** Data Types ************************************************************/

/**
 * IPFIX header helper.
 * Constitutes the first 16 bytes of every IPFIX Message
 */
typedef struct {
	uint16_t version;			/**< Expected to be 0x000a */
	uint16_t length; 
	uint32_t exportTime;
	uint32_t sequenceNo;
	uint32_t sourceId;
	byte   data;
	} IpfixHeader;

/**
 * NetflowV9 header helper.
 * Constitutes the first bytes of every NetflowV9 Message
 */
typedef struct {
	uint16_t version;                 /**< Expected to be 0x0009 */
	uint16_t setCount;
	uint32_t uptime;
	uint32_t exportTime;
	uint32_t sequenceNo;
	uint32_t sourceId;
	byte   data;
	} NetflowV9Header;
                                                                  
/**
 * IPFIX "Set" helper.
 * Constitutes the first bytes of every IPFIX Template Set, Options Template Set or Data Set
 */
typedef struct {
	uint16_t id;
	uint16_t length;
 	byte data; 
	} IpfixSetHeader;

/**
 * IPFIX "Template Set" helper.
 * Constitutes the first bytes of every IPFIX Template
 */
typedef struct {
	uint16_t templateId;
	uint16_t fieldCount;
	byte data;
	} IpfixTemplateHeader;

/**
 * IPFIX "DataTemplate Set" helper.
 * Constitutes the first bytes of every IPFIX DataTemplate
 */
typedef struct {
	uint16_t templateId;
	uint16_t fieldCount;
	uint16_t dataCount;
	uint16_t precedingRule;
	byte data;
	} IpfixDataTemplateHeader;

/**
 * IPFIX "Options Template Set" helper.
 * Constitutes the first bytes of every IPFIX Options Template
 */
typedef struct {
	uint16_t templateId;
	uint16_t fieldCount;
	uint16_t scopeCount; 
	byte data;
	} IpfixOptionsTemplateHeader;

/***** Global Variables ******************************************************/


/***** Internal Functions ****************************************************/

static void processDataSet(IpfixReceiver* ipfixReceiver, SourceID sourceID, IpfixSetHeader* set);
static void processTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceID, IpfixSetHeader* set);
static void processDataTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceID, IpfixSetHeader* set);
static void processOptionsTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceId, IpfixSetHeader* set);

/**
 * Processes an IPFIX template set.
 * Called by processMessage
 */
static void processTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceId, IpfixSetHeader* set) {
	byte* endOfSet = (byte*)set + ntohs(set->length);
	byte* record = (byte*)&set->data;

	/* TemplateSets are >= 4 byte, so we stop processing when only 3 bytes are left */
	while (record < endOfSet - 3) {
		IpfixTemplateHeader* th = (IpfixTemplateHeader*)record;
		record = (byte*)&th->data;
		if (th->fieldCount == 0) {
			/* This is a Template withdrawal message */
			destroyBufferedTemplate(ipfixReceiver->templateBuffer, sourceId, ntohs(th->templateId));
			continue;
			}
		BufferedTemplate* bt = (BufferedTemplate*)malloc(sizeof(BufferedTemplate));
		TemplateInfo* ti = (TemplateInfo*)malloc(sizeof(TemplateInfo));
		bt->sourceID = sourceId;
		bt->templateID = ntohs(th->templateId);
		bt->recordLength = 0;
		bt->setID = ntohs(set->id);
		bt->templateInfo = ti;
		ti->userData = 0;
		ti->templateId = ntohs(th->templateId);
		ti->fieldCount = ntohs(th->fieldCount);
		ti->fieldInfo = (FieldInfo*)malloc(ti->fieldCount * sizeof(FieldInfo));
		int isLengthVarying = 0;
		uint16_t fieldNo;
		for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) {
			ti->fieldInfo[fieldNo].type.id = ntohs(*(uint16_t*)((byte*)record+0));
			ti->fieldInfo[fieldNo].type.length = ntohs(*(uint16_t*)((byte*)record+2));
			ti->fieldInfo[fieldNo].offset = bt->recordLength; bt->recordLength+=ti->fieldInfo[fieldNo].type.length;
			if (ti->fieldInfo[fieldNo].type.length == 65535) isLengthVarying=1;
			if (ti->fieldInfo[fieldNo].type.id & IPFIX_ENTERPRISE_TYPE) {
				ti->fieldInfo[fieldNo].type.eid = ntohl(*(uint32_t*)((byte*)record+4));
				record = (byte*)((byte*)record+8);
				} else {
				ti->fieldInfo[fieldNo].type.eid = 0;
				record = (byte*)((byte*)record+4);
				}
			}
		if (isLengthVarying) {
  			bt->recordLength = 65535;
			for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) ti->fieldInfo[fieldNo].offset = 65535;
  			}
			
		bufferTemplate(ipfixReceiver->templateBuffer, bt); 
		// FIXME: Template expiration disabled for debugging
		// bt->expires = time(0) + TEMPLATE_EXPIRE_SECS;

		int n;		
		for (n = 0; n < ipfixReceiver->callbackCount; n++) {
			CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
			if (ci->templateCallbackFunction) ci->templateCallbackFunction(ci->handle, sourceId, ti);
			}
  		}
	}

/**
 * Processes an IPFIX Options Template Set.
 * Called by processMessage
 */
static void processOptionsTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceId, IpfixSetHeader* set) {
	byte* endOfSet = (byte*)set + ntohs(set->length);
	byte* record = (byte*)&set->data;

	/* OptionsTemplateSets are >= 4 byte, so we stop processing when only 3 bytes are left */
	while (record < endOfSet - 3) {
		IpfixOptionsTemplateHeader* th = (IpfixOptionsTemplateHeader*)record;
		record = (byte*)&th->data;
		if (th->fieldCount == 0) {
			/* This is a Template withdrawal message */
			destroyBufferedTemplate(ipfixReceiver->templateBuffer, sourceId, ntohs(th->templateId));
			continue;
			}
		BufferedTemplate* bt = (BufferedTemplate*)malloc(sizeof(BufferedTemplate));
		OptionsTemplateInfo* ti = (OptionsTemplateInfo*)malloc(sizeof(OptionsTemplateInfo));
		bt->sourceID = sourceId;
		bt->templateID = ntohs(th->templateId);
		bt->recordLength = 0;
		bt->setID = ntohs(set->id);
		bt->optionsTemplateInfo = ti;
		ti->userData = 0;
		ti->templateId = ntohs(th->templateId);
		ti->scopeCount = ntohs(th->scopeCount);
		ti->scopeInfo = (FieldInfo*)malloc(ti->scopeCount * sizeof(FieldInfo));
		ti->fieldCount = ntohs(th->fieldCount)-ntohs(th->scopeCount);
		ti->fieldInfo = (FieldInfo*)malloc(ti->fieldCount * sizeof(FieldInfo));
		int isLengthVarying = 0;
		uint16_t scopeNo;
		for (scopeNo = 0; scopeNo < ti->scopeCount; scopeNo++) {
			ti->scopeInfo[scopeNo].type.id = ntohs(*(uint16_t*)((byte*)record+0));
			ti->scopeInfo[scopeNo].type.length = ntohs(*(uint16_t*)((byte*)record+2));
			ti->scopeInfo[scopeNo].offset = bt->recordLength; bt->recordLength+=ti->scopeInfo[scopeNo].type.length;
			if (ti->scopeInfo[scopeNo].type.length == 65535) isLengthVarying=1;
			if (ti->scopeInfo[scopeNo].type.id & IPFIX_ENTERPRISE_TYPE) {
				ti->scopeInfo[scopeNo].type.eid = ntohl(*(uint32_t*)((byte*)record+4));
				record = (byte*)((byte*)record+8);
				} else {
				ti->fieldInfo[scopeNo].type.eid = 0;
				record = (byte*)((byte*)record+4);
				}
			}
		uint16_t fieldNo;
		for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) {
			ti->fieldInfo[fieldNo].type.id = ntohs(*(uint16_t*)((byte*)record+0));
			ti->fieldInfo[fieldNo].type.length = ntohs(*(uint16_t*)((byte*)record+2));
			ti->fieldInfo[fieldNo].offset = bt->recordLength; bt->recordLength+=ti->fieldInfo[fieldNo].type.length;
			if (ti->fieldInfo[fieldNo].type.length == 65535) isLengthVarying=1;
			if (ti->fieldInfo[fieldNo].type.id & IPFIX_ENTERPRISE_TYPE) {
				ti->fieldInfo[fieldNo].type.eid = ntohl(*(uint32_t*)((byte*)record+4));
				record = (byte*)((byte*)record+8);
				} else {
				ti->fieldInfo[fieldNo].type.eid = 0;
				record = (byte*)((byte*)record+4);
				}
			}
		if (isLengthVarying) {
  			bt->recordLength = 65535;
			for (fieldNo = 0; fieldNo < ti->scopeCount; fieldNo++) ti->scopeInfo[fieldNo].offset = 65535;
			for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) ti->fieldInfo[fieldNo].offset = 65535;
  			}
		bufferTemplate(ipfixReceiver->templateBuffer, bt); 
		// FIXME: Template expiration disabled for debugging
		// bt->expires = time(0) + TEMPLATE_EXPIRE_SECS;


		int n;		
		for (n = 0; n < ipfixReceiver->callbackCount; n++) {
			CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
			if (ci->optionsTemplateCallbackFunction) ci->optionsTemplateCallbackFunction(ci->handle, sourceId, ti);
			}
  		}
	}

/**
 * Processes an IPFIX DataTemplate set.
 * Called by processMessage
 */
static void processDataTemplateSet(IpfixReceiver* ipfixReceiver, SourceID sourceId, IpfixSetHeader* set) {
	byte* endOfSet = (byte*)set + ntohs(set->length);
	byte* record = (byte*)&set->data;

	/* DataTemplateSets are >= 4 byte, so we stop processing when only 3 bytes are left */
	while (record < endOfSet - 3) {
		IpfixDataTemplateHeader* th = (IpfixDataTemplateHeader*)record;
		record = (byte*)&th->data;
		if (th->fieldCount == 0) {
			/* This is a Template withdrawal message */
			destroyBufferedTemplate(ipfixReceiver->templateBuffer, sourceId, ntohs(th->templateId));
			continue;
			}
		BufferedTemplate* bt = (BufferedTemplate*)malloc(sizeof(BufferedTemplate));
		DataTemplateInfo* ti = (DataTemplateInfo*)malloc(sizeof(DataTemplateInfo));
		bt->sourceID = sourceId;
		bt->templateID = ntohs(th->templateId);
		bt->recordLength = 0;
		bt->setID = ntohs(set->id);
		bt->dataTemplateInfo = ti;
		ti->userData = 0;
		ti->id = ntohs(th->templateId);
		ti->preceding = ntohs(th->precedingRule);
		ti->fieldCount = ntohs(th->fieldCount);
		ti->dataCount = ntohs(th->dataCount);
		ti->fieldInfo = (FieldInfo*)malloc(ti->fieldCount * sizeof(FieldInfo));
		int isLengthVarying = 0;
		uint16_t fieldNo;
		for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) {
			ti->fieldInfo[fieldNo].type.id = ntohs(*(uint16_t*)((byte*)record+0));
			ti->fieldInfo[fieldNo].type.length = ntohs(*(uint16_t*)((byte*)record+2));
			ti->fieldInfo[fieldNo].offset = bt->recordLength; bt->recordLength+=ti->fieldInfo[fieldNo].type.length;
			if (ti->fieldInfo[fieldNo].type.length == 65535) isLengthVarying=1;
			if (ti->fieldInfo[fieldNo].type.id & IPFIX_ENTERPRISE_TYPE) {
				ti->fieldInfo[fieldNo].type.eid = ntohl(*(uint32_t*)((byte*)record+4));
				record = (byte*)((byte*)record+8);
				} else {
				ti->fieldInfo[fieldNo].type.eid = 0;
				record = (byte*)((byte*)record+4);
				}
			}
		if (isLengthVarying) {
			bt->recordLength = 65535;
			for (fieldNo = 0; fieldNo < ti->fieldCount; fieldNo++) ti->fieldInfo[fieldNo].offset = 65535;
			}

		ti->dataInfo = (FieldInfo*)malloc(ti->fieldCount * sizeof(FieldInfo));
		for (fieldNo = 0; fieldNo < ti->dataCount; fieldNo++) {
			ti->dataInfo[fieldNo].type.id = ntohs(*(uint16_t*)((byte*)record+0));
			ti->dataInfo[fieldNo].type.length = ntohs(*(uint16_t*)((byte*)record+2));
			if (ti->dataInfo[fieldNo].type.id & IPFIX_ENTERPRISE_TYPE) {
				ti->dataInfo[fieldNo].type.eid = ntohl(*(uint32_t*)((byte*)record+4));
				record = (byte*)((byte*)record+8);
				} else {
				ti->dataInfo[fieldNo].type.eid = 0;
				record = (byte*)((byte*)record+4);
				}
			}
		
		/* done with reading dataInfo, @c record now points to the fixed data block */
		byte* dataStart = record;
		
		int dataLength = 0;
		for (fieldNo = 0; fieldNo < ti->dataCount; fieldNo++) {
			ti->dataInfo[fieldNo].offset = dataLength;
			if (ti->dataInfo[fieldNo].type.length == 65535) {
				/* This is a variable-length field, get length from first byte and advance offset */
				ti->dataInfo[fieldNo].type.length = *(uint8_t*)(dataStart + ti->dataInfo[fieldNo].offset);
				ti->dataInfo[fieldNo].offset += 1;
				if (ti->dataInfo[fieldNo].type.length == 255) {
					/* First byte did not suffice, length is stored in next two bytes. Advance offset */
					ti->dataInfo[fieldNo].type.length = *(uint16_t*)(dataStart + ti->dataInfo[fieldNo].offset);
					ti->dataInfo[fieldNo].offset += 2;
					}
				}
			dataLength += ti->dataInfo[fieldNo].type.length;
			}
			
		/* Copy fixed data block */
		ti->data = (byte*)malloc(dataLength);
		memcpy(ti->data,dataStart,dataLength);

		/* Advance record to end of fixed data block, i.e. start of next template*/
		record += dataLength;
		
		bufferTemplate(ipfixReceiver->templateBuffer, bt); 
		// FIXME: Template expiration disabled for debugging
		// bt->expires = time(0) + TEMPLATE_EXPIRE_SECS;

		int n;		
		for (n = 0; n < ipfixReceiver->callbackCount; n++) {
			CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
			if (ci->dataTemplateCallbackFunction) ci->dataTemplateCallbackFunction(ci->handle, sourceId, ti);
			}
  		}
	}

/**
 * Processes an IPFIX data set.
 * Called by processMessage
 */
static void processDataSet(IpfixReceiver* ipfixReceiver, SourceID sourceId, IpfixSetHeader* set) {
	BufferedTemplate* bt = getBufferedTemplate(ipfixReceiver->templateBuffer, sourceId, ntohs(set->id));

	if(bt == 0) {
                /* this error may come in rapid succession; I hope I don't regret it */
		msg(MSG_INFO, "Template %d unknown to collecting process", ntohs(set->id));
		return;
	}
	
	#ifdef SUPPORT_NETFLOWV9
	if ((bt->setID == IPFIX_SetId_Template) || (bt->setID == NetflowV9_SetId_Template)) {
	#else
	if (bt->setID == IPFIX_SetId_Template) {
	#endif

		TemplateInfo* ti = bt->templateInfo;

		uint16_t length = ntohs(set->length)-((byte*)(&set->data)-(byte*)set);

		byte* record = &set->data;
	
		if (bt->recordLength < 65535) {
			byte* recordX = record+length;

			if (record >= recordX - (bt->recordLength - 1)) {
				DPRINTF("Got a Data Set that contained not a single full record\n");
			}

			/* We stop processing when no full record is left */
			while (record < recordX - (bt->recordLength - 1)) {
				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					ipfixReceiver->receivedRecords++;
					if (ci->dataRecordCallbackFunction) ci->dataRecordCallbackFunction(ci->handle, sourceId, ti, bt->recordLength, record);
					}
				record = record + bt->recordLength;
				}
			} else {
			byte* recordX = record+length;

			if (record >= recordX - 3) {
				DPRINTF("Got a Data Set that contained not a single full record");
			}

			/* We assume that all variable-length records are >= 4 byte, so we stop processing when only 3 bytes are left */
			while (record < recordX - 3) {
				int recordLength=0;
				int i;
				for (i = 0; i < ti->fieldCount; i++) {
					int fieldLength = 0;
					if (ti->fieldInfo[i].type.length < 65535) {
						fieldLength = ti->fieldInfo[i].type.length;
						} else {
						if (*(byte*)record < 255) {
							fieldLength = *(byte*)record;
							} else {
							fieldLength = *(uint16_t*)(record+1);
							}
						}
					ti->fieldInfo[i].type.length = fieldLength;
					ti->fieldInfo[i].offset = recordLength;
					recordLength += fieldLength;
					}
				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					ipfixReceiver->receivedRecords++;
					if (ci->dataRecordCallbackFunction) ci->dataRecordCallbackFunction(ci->handle, sourceId, ti, recordLength, record);
					}
				record = record + recordLength;
				}
			}
		} else 
	if (bt->setID == IPFIX_SetId_OptionsTemplate) {
  	
		OptionsTemplateInfo* ti = bt->optionsTemplateInfo;

		uint16_t length = ntohs(set->length)-((byte*)(&set->data)-(byte*)set);
		byte* record = &set->data;
	
		if (bt->recordLength < 65535) {
			byte* recordX = record+length;
			while (record < recordX) {
				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					if (ci->optionsRecordCallbackFunction) ci->optionsRecordCallbackFunction(ci->handle, sourceId, ti, bt->recordLength, record);
					}
				record = record + bt->recordLength;
				}
			} else {
			byte* recordX = record+length;
			while (record < recordX) {
				int recordLength=0;
				int i;
				for (i = 0; i < ti->scopeCount; i++) {
					int fieldLength = 0;
					if (ti->scopeInfo[i].type.length < 65535) {
						fieldLength = ti->scopeInfo[i].type.length;
						} else {
						if (*(byte*)record < 255) {
							fieldLength = *(byte*)record;
							} else {
							fieldLength = *(uint16_t*)(record+1);
							}
						}
					ti->scopeInfo[i].type.length = fieldLength;
					ti->scopeInfo[i].offset = recordLength;
					recordLength += fieldLength;
					}
				for (i = 0; i < ti->fieldCount; i++) {
					int fieldLength = 0;
					if (ti->fieldInfo[i].type.length < 65535) {
						fieldLength = ti->fieldInfo[i].type.length;
						} else {
						if (*(byte*)record < 255) {
							fieldLength = *(byte*)record;
							} else {
							fieldLength = *(uint16_t*)(record+1);
							}
						}
					ti->fieldInfo[i].type.length = fieldLength;
					ti->fieldInfo[i].offset = recordLength;
					recordLength += fieldLength;
					}

				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					if (ci->optionsRecordCallbackFunction) ci->optionsRecordCallbackFunction(ci->handle, sourceId, ti, recordLength, record);
					}

				record = record + recordLength;
				}
			}
		} else 
  	if (bt->setID == IPFIX_SetId_DataTemplate) {
		DataTemplateInfo* ti = bt->dataTemplateInfo;

		uint16_t length = ntohs(set->length)-((byte*)(&set->data)-(byte*)set);
		byte* record = &set->data;

		if (bt->recordLength < 65535) {
			byte* recordX = record+length;
			while (record < recordX) {
				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					ipfixReceiver->receivedRecords++;
					if (ci->dataDataRecordCallbackFunction) ci->dataDataRecordCallbackFunction(ci->handle, sourceId, ti, bt->recordLength, record);
					}
				record = record + bt->recordLength;
				}
			} else {
			byte* recordX = record+length;
			while (record < recordX) {
				int recordLength=0;
				int i;
				for (i = 0; i < ti->fieldCount; i++) {
					int fieldLength = 0;
					if (ti->fieldInfo[i].type.length < 65535) {
						fieldLength = ti->fieldInfo[i].type.length;
						} else {
						if (*(byte*)record < 255) {
							fieldLength = *(byte*)record;
							} else {
							fieldLength = *(uint16_t*)(record+1);
							}
						}
					ti->fieldInfo[i].type.length = fieldLength;
					ti->fieldInfo[i].offset = recordLength;
					recordLength += fieldLength;
					}
				int n;		
				for (n = 0; n < ipfixReceiver->callbackCount; n++) {
					CallbackInfo* ci = &ipfixReceiver->callbackInfo[n];
					ipfixReceiver->receivedRecords++;
					if (ci->dataDataRecordCallbackFunction) ci->dataDataRecordCallbackFunction(ci->handle, sourceId, ti, recordLength, record);
					}
				record = record + recordLength;
			}
			}
		} else {
		msg(MSG_FATAL, "Data Set based on known but unhandled template type %d", bt->setID);
		}
}
	

/**
 * Process a NetflowV9 Packet
 * @return 0 on success
 */	
static int processNetflowV9Packet(IpfixReceiver *ipfixReceiver, byte *message, uint16_t length) {
	uint16_t tmpid;
	SourceID tmpsid;
	int i, n;

	NetflowV9Header *header = (NetflowV9Header *)message;
	
	/* pointer to first set */
	IpfixSetHeader *set = (IpfixSetHeader *)&header->data;
        n=ntohs(header->setCount);

	for(i = 0; i < n; i++) {
		tmpid=ntohs(set->id);
                tmpsid=ntohl(header->sourceId);

		if(tmpid >= IPFIX_SetId_Data_Start) {
			processDataSet(ipfixReceiver, tmpsid, set);
		} else if(tmpid == NetflowV9_SetId_Template) {
			processTemplateSet(ipfixReceiver, tmpsid, set);
		} else {
			msg(MSG_ERROR, "processNetflowV9: Unsupported Set ID - expected 0/256+, got %d", tmpid);
		}

		set = (IpfixSetHeader *)((byte *)set + ntohs(set->length));
	}

	return 0;
}

/**
 * Process an IPFIX Packet
 * @return 0 on success
 */	
static int processIpfixPacket(IpfixReceiver* ipfixReceiver, byte* message, uint16_t length) {
	uint16_t tmpid;
	SourceID tmpsid;
	IpfixHeader* header = (IpfixHeader*)message;

	if(ntohs(header->length) != length) {
 		DPRINTF("Bad message length - expected %#06x, got %#06x\n", length, ntohs(header->length));
		return -1;
	}

	/* pointer to first set */
	IpfixSetHeader* set = (IpfixSetHeader*)&header->data;

	/* pointer beyond message */
	IpfixSetHeader* setX = (IpfixSetHeader*)((char*)message + length); 

	while(set < setX) {
		tmpid=ntohs(set->id);
                tmpsid=ntohl(header->sourceId);
		
		switch(tmpid) {

		case IPFIX_SetId_DataTemplate:
			processDataTemplateSet(ipfixReceiver, tmpsid, set);
                        break;
		case IPFIX_SetId_Template:
			processTemplateSet(ipfixReceiver, tmpsid, set);
                        break;
		case IPFIX_SetId_OptionsTemplate:
			processOptionsTemplateSet(ipfixReceiver, tmpsid, set);
			break;
		default:
                        if(tmpid >= IPFIX_SetId_Data_Start) {
                                processDataSet(ipfixReceiver, tmpsid, set);
                        } else {
                                msg(MSG_ERROR, "processIpfixPacket: Unsupported Set ID - expected 2/3/4/256+, got %d", tmpid);
                        }
                }

		set = (IpfixSetHeader*)((byte*)set + ntohs(set->length));
	}

	return 0;
}

/**
 * Process new Message
 * @return 0 on success
 */	
static int processMessage(IpfixReceiver* ipfixReceiver, byte* message, uint16_t length) {
	IpfixHeader* header = (IpfixHeader*)message;
	if (ntohs(header->version) == 0x000a) {
		return processIpfixPacket(ipfixReceiver, message, length);
		}
	#ifdef SUPPORT_NETFLOWV9
	if (ntohs(header->version) == 0x0009) {
		return processNetflowV9Packet(ipfixReceiver, message, length);
		}
	DPRINTF("Bad message version - expected 0x009 or 0x000a, got %#06x\n", ntohs(header->version));
	return -1;
	#else
	DPRINTF("Bad message version - expected 0x000a, got %#06x\n", ntohs(header->version));
	return -1;
	#endif
	}
	
static void printIPv4(FieldType type, FieldData* data) {
	int octet1 = 0;
	int octet2 = 0;
	int octet3 = 0;
	int octet4 = 0;
	int imask = 0;
	if (type.length >= 1) octet1 = data[0];
	if (type.length >= 2) octet2 = data[1];
	if (type.length >= 3) octet3 = data[2];
	if (type.length >= 4) octet4 = data[3];
	if (type.length >= 5) imask = data[4];
	if (type.length > 5) {
		DPRINTF("IPv4 Address with length %d unparseable\n", type.length);
		return;
		}
	
	if ((type.length == 5) /*&& (imask != 0)*/) {
		printf("%d.%d.%d.%d/%d", octet1, octet2, octet3, octet4, 32-imask);
		} else {
		printf("%d.%d.%d.%d", octet1, octet2, octet3, octet4);
		}
	}

static void printPort(FieldType type, FieldData* data) {
	if (type.length == 0) {
		printf("zero-length Port");
		return;
		}
	if (type.length == 2) {
		int port = ((uint16_t)data[0] << 8)+data[1];
		printf("%d", port);
		return;
		}
	if ((type.length >= 4) && ((type.length % 4) == 0)) {
		int i;
		for (i = 0; i < type.length; i+=4) {
			int starti = ((uint16_t)data[i+0] << 8)+data[i+1];
			int endi = ((uint16_t)data[i+2] << 8)+data[i+3];
			if (i > 0) printf(",");
			if (starti != endi) {
				printf("%d:%d", starti, endi);
				} else {
				printf("%d", starti);
				}
			} 
		return;
		}
	
	printf("Port with length %d unparseable", type.length);
	}

void printProtocol(FieldType type, FieldData* data) {
	if (type.length != 1) {
		printf("Protocol with length %d unparseable", type.length);
		return;
		}
	switch (data[0]) {
		case IPFIX_protocolIdentifier_ICMP:
			printf("ICMP");
			return;
		case IPFIX_protocolIdentifier_TCP:
			printf("TCP");
			return;
		case IPFIX_protocolIdentifier_UDP: 
			printf("UDP");
			return;
		case IPFIX_protocolIdentifier_RAW: 
			printf("RAW");
			return;
		default:
			printf("unknownProtocol");
			return;
		}
	}

static void printUint(FieldType type, FieldData* data) {
	switch (type.length) {
		case 1:
			printf("%hhu",*(uint8_t*)data);
			return;
		case 2:
			printf("%hu",ntohs(*(uint16_t*)data));
			return;
		case 4:
			printf("%u",ntohl(*(uint32_t*)data));
			return;
		case 8:
			printf("%Lu",ntohll(*(uint64_t*)data));
			return;
		default:
			printf("Uint with length %d unparseable", type.length);
			return;
		}
	}

/**
 * this is the main thread loop for the ipfix receiver
 * data is read from the network and dispatched via processMessage()
 * TODO: if we block in recvfrom(), we won't exit the thread!
 */
static void * listenerUdpIpv4(void *ipfixReceiver)
{
	int n;
	struct sockaddr_in clientAddress;
	socklen_t clientAddressLen;

	clientAddressLen = sizeof(struct sockaddr_in);

	IpfixReceiver *ipr = (IpfixReceiver *)ipfixReceiver;
	byte *data = (byte *)malloc(sizeof(byte)*MAX_MSG_LEN);
	
        msg(MSG_INFO, "IPFIX receiver: now running IPFIXReceiver thread");
	
	while(!ipr->exit) {
		/* if we block here, exiting of this thread is delayed until the next packet :( */
		n = recvfrom(ipr->socket, data, MAX_MSG_LEN, 0, (struct sockaddr*)&clientAddress, &clientAddressLen);

		if(n < 0) {
			msg(MSG_DEBUG, "recvfrom returned with error, terminating UDP/IPv4 listener thread");
			break;
		}
                DPRINTF("IPFIXReceiver: got data with len %d\n", n);

		pthread_mutex_lock(&ipr->mutex);
		processMessage(ipr, data, n);
		pthread_mutex_unlock(&ipr->mutex);
	}

        msg(MSG_DEBUG, "IPFIXReceiver thread (listener) is terminating");
	free(data);

	return 0;
}

/***** Exported Functions ****************************************************/

/**
 * Initializes internal data.
 * Call once before using any function in this module
 * @return 0 if call succeeded
 */
int initializeIpfixReceivers() {
	return 0;
}

/**
 * Destroys internal data.
 * Call once to tidy up. Do not use any function in this module afterwards
 * @return 0 if call succeeded
 */
int deinitializeIpfixReceivers() {
	return 0;
}

/**
 * Prints a string representation of FieldData to stdout.
 */
void printFieldData(FieldType type, FieldData* pattern) {
	char* s;
	
	switch (type.id) {
		case IPFIX_TYPEID_protocolIdentifier:
			printf("protocolIdentifier:");
			printProtocol(type, pattern);
			break;
		case IPFIX_TYPEID_sourceIPv4Address:
			printf("sourceIPv4Address:");
			printIPv4(type, pattern);
			break;
		case IPFIX_TYPEID_destinationIPv4Address:
			printf("destinationIPv4Address:");
			printIPv4(type, pattern);
			break;				
		case IPFIX_TYPEID_sourceTransportPort:
			printf("sourceTransportPort:");
			printPort(type, pattern);
			break;
		case IPFIX_TYPEID_destinationTransportPort:
			printf("destinationTransportPort:");
			printPort(type, pattern);
			break;
		default:
			s = typeid2string(type.id);
			if (s != NULL) {
				printf("%s:", s);
				printUint(type, pattern);
				} else {
				DPRINTF("Field with ID %d unparseable\n", type.id);
				}
			break;
		}
}

/**
 * Gets a Template's FieldInfo by field id.
 * @param ti Template to search in
 * @param type Field id and field eid to look for, length is ignored
 * @return NULL if not found
 */
FieldInfo* getTemplateFieldInfo(TemplateInfo* ti, FieldType* type) {
	int i;
	
	for (i = 0; i < ti->fieldCount; i++) {
		if ((ti->fieldInfo[i].type.id == type->id) && (ti->fieldInfo[i].type.eid == type->eid)) {
			return &ti->fieldInfo[i];
			}
		}

	return NULL;
}

/**
 * Gets a DataTemplate's FieldInfo by field id.
 * @param ti DataTemplate to search in
 * @param type Field id and field eid to look for, length is ignored
 * @return NULL if not found
 */
FieldInfo* getDataTemplateFieldInfo(DataTemplateInfo* ti, FieldType* type) {
	int i;
	
	for (i = 0; i < ti->fieldCount; i++) {
		if ((ti->fieldInfo[i].type.id == type->id) && (ti->fieldInfo[i].type.eid == type->eid)) {
			return &ti->fieldInfo[i];
			}
		}

	return NULL;
}

/**
 * Gets a DataTemplate's Data-FieldInfo by field id.
 * @param ti DataTemplate to search in
 * @param type Field id and field eid to look for, length is ignored
 * @return NULL if not found
 */
FieldInfo* getDataTemplateDataInfo(DataTemplateInfo* ti, FieldType* type) {
	int i;
	
	for (i = 0; i < ti->dataCount; i++) {
		if ((ti->dataInfo[i].type.id == type->id) && (ti->dataInfo[i].type.eid == type->eid)) {
			return &ti->dataInfo[i];
			}
		}

	return NULL;		
}
	
/**
 * Adds a set of callback functions to the list of functions to call when a new Message arrives
 * @param ipfixReceiver IpfixReceiver to set the callback function for
 * @param handles set of callback functions
 */
void addIpfixReceiverCallbacks(IpfixReceiver* ipfixReceiver, CallbackInfo handles) {
	int n = ++ipfixReceiver->callbackCount;
	ipfixReceiver->callbackInfo = (CallbackInfo*)realloc(ipfixReceiver->callbackInfo, n * sizeof(CallbackInfo));
	memcpy(&ipfixReceiver->callbackInfo[n-1], &handles, sizeof(CallbackInfo));
}

/**
 * Creates a new IpfixReceiver.
 * Call @c startIpfixReceiver() to start processing messages.
 * @param port Port to listen on
 * @return handle for further interaction
 */
IpfixReceiver* createIpfixReceiver(uint16_t port) {
	IpfixReceiver* ipfixReceiver;
	struct sockaddr_in serverAddress;
	

        msg(MSG_DEBUG, "IPFIXReceiver: making for port %d", port);

        if(!(ipfixReceiver=(IpfixReceiver*)malloc(sizeof(IpfixReceiver)))) {
		msg(MSG_FATAL, "Ran out of memory");
		goto out0;
	}

	ipfixReceiver->callbackInfo=0;
        ipfixReceiver->callbackCount=0;
	ipfixReceiver->exit=0;
	ipfixReceiver->receivedRecords=0;

	if(!(ipfixReceiver->templateBuffer = createTemplateBuffer(ipfixReceiver))) {
		msg(MSG_FATAL, "Could not create template Buffer");
		goto out1;
	}

	if (pthread_mutex_init(&ipfixReceiver->mutex, NULL) != 0) {
		msg(MSG_FATAL, "Could not init mutex");
		goto out2;
	}
		
	if (pthread_mutex_lock(&ipfixReceiver->mutex) != 0) {
		msg(MSG_FATAL, "Could not lock mutex");
		goto out2;
	}

	ipfixReceiver->socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(ipfixReceiver->socket < 0) {
		msg(MSG_FATAL, "Could not create socket");
		goto out2;
	}

	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddress.sin_port = htons(port);
	if(bind(ipfixReceiver->socket, (struct sockaddr*)&serverAddress, sizeof(struct sockaddr_in)) < 0) {
		msg(MSG_FATAL, "Could not bind socket");
		goto out3;
	}

	if(pthread_create(&(ipfixReceiver->thread), NULL, listenerUdpIpv4, ipfixReceiver) != 0) {
		msg(MSG_FATAL, "Could not pthread_create listener thread");
		goto out3;
	}
	//listenerUdpIpv4(ipfixReceiver); //debug - single-threaded
	
        return ipfixReceiver;

out3:
	close(ipfixReceiver->socket);
out2:
	destroyTemplateBuffer(ipfixReceiver->templateBuffer);
out1:
	free(ipfixReceiver);
out0:
	return NULL;
}

/**
 * Starts processing messages.
 * All sockets prepared by calls to createIpfixReceiver() will start
 * receiving messages until stopIpfixReceiver() is called.
 * @return 0 on success, non-zero on error
 */
int startIpfixReceiver(IpfixReceiver* ipfixReceiver)
{
	if(pthread_mutex_unlock(&ipfixReceiver->mutex) != 0) {
		return -1;
	}
	
	return 0;
}
	
/**
 * Stops processing messages.
 * No more messages will be processed until the next startIpfixReceiver() call.
 * @return 0 on success, non-zero on error
 */
int stopIpfixReceiver(IpfixReceiver* ipfixReceiver)
{
	if(pthread_mutex_lock(&ipfixReceiver->mutex) != 0) {
		return -1;
	}

	return 0;
}

/**
 * Tells the receiver thread to shut down
 * @return 0 on success from pthread_join, non-zero on error
 */
int shutdownIpfixReceiver(IpfixReceiver *ipr)
{
	void *ret;

	ipr->exit=1;

	/*
	 Don't know if it is wise to really WAIT for the thread and not only
	 detach it - may deadlock
	 */
	return(pthread_join(ipr->thread, &ret));
}

/**
 * Frees memory used by a IpfixReceiver.
 * @param ipfixReceiver Handle returned by @c createIpfixReceiver()
 */
void destroyIpfixReceiver(IpfixReceiver* ipfixReceiver) {
	close(ipfixReceiver->socket);
	
	if (pthread_mutex_unlock(&ipfixReceiver->mutex) != 0) {
		DPRINTF("Could not unlock mutex\n");
	}
	
	destroyTemplateBuffer(ipfixReceiver->templateBuffer);
	free(ipfixReceiver->callbackInfo);
	free(ipfixReceiver);
}

/**
 * Called by the logger timer thread. Dumps info using msg_stat
 */
void statsIpfixReceiver(void* ipfixReceiver_)
{
	IpfixReceiver* ipfixReceiver = (IpfixReceiver*)ipfixReceiver_;

	msg_stat("Concentrator: IpfixReceiver: %6d records received", ipfixReceiver->receivedRecords);
	ipfixReceiver->receivedRecords = 0;
}
