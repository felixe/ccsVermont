/*
 * IPFIX Intrusion Detection System Module
 * Copyright (C) 2017 Felix Erlacher
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

#include "IpfixIds.hpp"
#include "common/Time.h"
#include "common/Misc.h"
#include "Connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/**
 * Creates a new IpfixIds.
 * Do not forget to call @c startIpfixIds() to begin printing
 * @return handle to use when calling @c destroyIpfixIds()
 */
IpfixIds::IpfixIds(string alertFileString)
{

    lastTemplate = 0;
	string file = "";
	alertFile = stdout;

	//open alertfile for writing
	if (alertFileString == "NULL") {
        THROWEXCEPTION("IpfixIds: no alertfile given, aborting!");
	}else{
		alertFile = fopen(alertFileString.c_str(), "w");
		if (!alertFile)
			THROWEXCEPTION("IpfixIds: error opening alertfile '%s': %s (%u)", alertFileString.c_str(), strerror(errno), errno);
	}

    //be nice and tell people what the configuration is
    msg(MSG_INFO, "IpfixIds started with following parameters:");
    msg(MSG_INFO, "  - Alertfile = %s", alertFileString.c_str());
}

/**
 * Frees memory used by an IpfixIds
 */
IpfixIds::~IpfixIds()
{
	//close alertfile before shutdown
		int ret = fclose(alertFile);
		if (ret){
			THROWEXCEPTION("IpfixIds: error closing file '%s': %s (%u)", alertFileString.c_str(), strerror(errno), errno);
        }
}


/**
 * called on reception of Ipfix record
 */
void IpfixIds::onDataRecord(IpfixDataRecord* record)
{
        IpfixRecord::Data* uriData;
        IpfixRecord::Data* hostData;
        InformationElement::IeInfo hostRecordType;
        InformationElement::IeInfo uriRecordType;
        if(record->templateInfo->setId == TemplateInfo::IpfixOptionsTemplate) {
            THROWEXCEPTION("IpfixOptionsTemplate arrived, implement something to ignore  it, and hand over");
        }
        if(record->templateInfo->setId == TemplateInfo::IpfixDataTemplate) {
            THROWEXCEPTION("IpfixDataTemplate arrived, implement something to ignore  it, and hand over");
        }

	    //go through ipfix record IE fields
        for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
            if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestMethod, 0)) {
                            IpfixRecord::Data* fieldData = (record->data + record->templateInfo->fieldInfo[i].offset);
                            if(fieldData[0]=='G'&&fieldData[1]=='E'&&fieldData[2]=='T'){
                            }
            }
            if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestTarget, 0)) {
                            uriData = (record->data + record->templateInfo->fieldInfo[i].offset);
                            uriRecordType=record->templateInfo->fieldInfo[i].type;
            }
            if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestHost, 0)) {
                            hostData = (record->data + record->templateInfo->fieldInfo[i].offset);
                            hostRecordType=record->templateInfo->fieldInfo[i].type;
            }
        }
        //print interesting stuff for this record
        fprintf(alertFile,"GET request to, host: ");
        printPayload(hostRecordType,hostData,0,alertFile);
        fprintf(alertFile,", with uri: ");
        printPayload(uriRecordType,uriData,0,alertFile);
        fprintf(alertFile,"found\n");
//printFieldData(record->templateInfo->fieldInfo[i].type, (record->data + record->templateInfo->fieldInfo[i].offset));
	//to not hand over record but remove your references to it
	//record->removeReference();

	//hand record to next module
	send(record);
}

/**
*called on reception of ipfix template
*/
void IpfixIds::onTemplate(IpfixTemplateRecord* record)
{
	//at the moment do nothing
	record->removeReference();
}

/**
*called on reception of template announced to be destroyed
*/
void IpfixIds::onTemplateDestruction(IpfixTemplateDestructionRecord* record)
{
	//at the moment do nothing
	record->removeReference();
}

/**
* helper function to print text data to a file
*/
void IpfixIds::printPayload(InformationElement::IeInfo type, IpfixRecord::Data* data, bool showOmittedZeroBytes,FILE* file)
{
	int64_t lastPrintedCharacter = -1;
	//fprintf(file,"type =%s ",type.toString().c_str());
    //fprintf(file,"length = %d\n", type.length);
	fprintf(file, "'");
	for (uint32_t i=0; i<type.length; i++) {
		char c = data[i];

		if (c!=0) {
			if (i && lastPrintedCharacter) {
				lastPrintedCharacter++;
				for (;lastPrintedCharacter<i;lastPrintedCharacter++)
					fprintf(file, ".");
			}
			lastPrintedCharacter = i;
		}

		if (isprint(c)) fprintf(file, "%c", c);
		else {
			const char *special = 0;
			switch (c) {
			case 0: break;
			case '\n': special = "\\n"; break;
			case '\r': special = "\\r"; break;
			case '\t': special = "\\t"; break;
			default : special = ".";
			}
			if (special) fprintf(file, "%s", special);
		}
	}
	fprintf(file, "'");
	if (showOmittedZeroBytes && lastPrintedCharacter+1<type.length) {
		fprintf(file, " --> Not displaying %ld trailing zero-bytes", type.length-(lastPrintedCharacter+1));
	}
}
