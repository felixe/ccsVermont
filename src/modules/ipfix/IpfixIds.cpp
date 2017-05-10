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

int alertCounter;

/**
 * Creates a new IpfixIds.
 * Do not forget to call @c startIpfixIds() to begin printing
 * @return handle to use when calling @c destroyIpfixIds()
 */
IpfixIds::IpfixIds(string alertFileString, string rulesFileString, bool printParsedRules)
{
	alertCounter=0;
    lastTemplate = 0;
	string file = "";
	alertFile = stdout;
	string line;
	FILE* rulesFile;

    SnortRuleParser ruleParser;

	//open alertfile for writing
	if (alertFileString == "NULL") {
        THROWEXCEPTION("IpfixIds: no alertfile given, aborting!");
	}else{
		alertFile = fopen(alertFileString.c_str(), "w");
		//also tell the printhelper to use alertfile to print and not stdout
		printer.changeFile(alertFile);
		if (!alertFile)
			THROWEXCEPTION("IpfixIds: error opening alertfile '%s': %s (%u)", alertFileString.c_str(), strerror(errno), errno);
	}

	if (rulesFileString == "NULL") {
        THROWEXCEPTION("IpfixIds: no rulesfile given, aborting!");
	}else{
        rulesFile = fopen(rulesFileString.c_str(), "r");
		if (!rulesFile){
			THROWEXCEPTION("IpfixIds: error opening rulesfile '%s': %s (%u)", rulesFileString.c_str(), strerror(errno), errno);
        }else{
            //just checkin' rule is opened again in the parser
            int ret = fclose(rulesFile);
            if (ret){
                THROWEXCEPTION("IpfixIds: error closing rulesfile '%s': %s (%u). This should not happen!!!", rulesFileString.c_str(), strerror(errno), errno);
            }
        }
	}
    //be nice and tell people what the configuration is
    msg(MSG_INFO, "IpfixIds started with following parameters:");
    msg(MSG_INFO, "  - Alertfile = %s", alertFileString.c_str());
    msg(MSG_INFO, "  - Rulesfile = %s", rulesFileString.c_str());
    msg(MSG_INFO, "IpfixIds: starting to parse rulesfile");
    rules=ruleParser.parseMe(rulesFileString.c_str());
    if(rules.size()>0){
        msg(MSG_DIALOG, "IpfixIds: %d rules parsed succesfully",rules.size());
    }else{
        THROWEXCEPTION("0 rules parsed from rulesfile %s. Does this file contain properly formattet Snort rules?",rulesFileString.c_str());
    }

    //do basic plausability test, if this fails than there is a bug in the parser
    for(unsigned long i=0;i<rules.size();i++){
            ruleParser.compareVectorSizes(&rules[i]);
    }

    if(printParsedRules){
        fprintf(stdout,"------------------------------------------------------\n");
        fprintf(stdout,"The following rules have been parsed from rulesfile %s\n", rulesFileString.c_str());
        fprintf(stdout,"------------------------------------------------------\n");
        for(unsigned long i=0;i<rules.size();i++){
            ruleParser.printSnortRule(&rules[i]);
        }
        fprintf(stdout,"------------------------------------------------------\n");
    }

}

/**
 * Frees memory used by an IpfixIds
 */
IpfixIds::~IpfixIds()
{
	msg(MSG_DIALOG,"IpfixIds: %d alerts triggered",alertCounter);
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

    unsigned long i;
    unsigned long j;
    unsigned long k;
    bool writeAlertBool;
    string methodString;
    string uriString;
    string statusMsgString;
    string statusCodeString;


    //TODO is it more efficient if we leave the data pointer away and convert to string directly?
    IpfixRecord::Data* uriData;
    IpfixRecord::Data* hostData;
    IpfixRecord::Data* methodData;
    IpfixRecord::Data* statusMsgData;
    IpfixRecord::Data* statusCodeData;
    IpfixRecord::Data* sourceIPData;
    IpfixRecord::Data* destinationIPData;
    IpfixRecord::Data* sourcePortData;
    IpfixRecord::Data* destinationPortData;
    IpfixRecord::Data* startData;


    InformationElement::IeInfo uriType;
    InformationElement::IeInfo hostType;
    InformationElement::IeInfo methodType;
    InformationElement::IeInfo statusMsgType;
    InformationElement::IeInfo statusCodeType;
    InformationElement::IeInfo sourceIPType;
    InformationElement::IeInfo destinationIPType;
    InformationElement::IeInfo sourcePortType;
    InformationElement::IeInfo destinationPortType;
    InformationElement::IeInfo startType;


    if(record->templateInfo->setId == TemplateInfo::IpfixOptionsTemplate) {
        THROWEXCEPTION("IpfixOptionsTemplate arrived, implement something to ignore it, and hand over");
    }
    if(record->templateInfo->setId == TemplateInfo::IpfixDataTemplate) {
        THROWEXCEPTION("IpfixDataTemplate arrived, implement something to ignore it, and hand over");
    }

    //go through ipfix record IE fields and save pointers to interesting fields
    for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestMethod, 0)) {
			 methodData = (record->data + record->templateInfo->fieldInfo[i].offset);
			 methodString= std::string((const char*)methodData);
			 methodType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestTarget, 0)) {
			uriData = (record->data + record->templateInfo->fieldInfo[i].offset);
			uriString = std::string((const char*)uriData);
			uriType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpStatusCode, 0)) {
			statusCodeData = (record->data + record->templateInfo->fieldInfo[i].offset);
			statusCodeString = std::string((const char*)statusCodeData);
			statusCodeType=record->templateInfo->fieldInfo[i].type;
        }
        //TODO convert also this type to IANA registered type
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_ETYPEID_httpStatusPhrase, 0)) {
        	statusMsgData = (record->data + record->templateInfo->fieldInfo[i].offset);
            statusMsgString = std::string((const char*)statusMsgData);
            statusMsgType=record->templateInfo->fieldInfo[i].type;
        }
//        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestHost, 0)) {
//                        hostData = (record->data + record->templateInfo->fieldInfo[i].offset);
//                        hostRecordType=record->templateInfo->fieldInfo[i].type;
//        }

        //stuff that we need for a meaningful alert
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_sourceIPv4Address, 0)) {
			sourceIPData = (record->data + record->templateInfo->fieldInfo[i].offset);
			sourceIPType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_destinationIPv4Address, 0)) {
			destinationIPData = (record->data + record->templateInfo->fieldInfo[i].offset);
			destinationIPType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_sourceTransportPort, 0)) {
			sourcePortData = (record->data + record->templateInfo->fieldInfo[i].offset);
			sourcePortType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_destinationTransportPort, 0)) {
			destinationPortData = (record->data + record->templateInfo->fieldInfo[i].offset);
			destinationPortType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_flowStartNanoSeconds, 0)) {
			startData = (record->data + record->templateInfo->fieldInfo[i].offset);
			startType=record->templateInfo->fieldInfo[i].type;
        }
    }

    //check against rules:
    //TODO: consider nocase keyword
    for(i=0;i<rules.size();i++){
    	bool contentMatched[rules[i].body.content.size()]={0};
    	//contentModifier vector MUST have same size than content vector
        for(j=0;j<rules[i].body.contentModifierHTTP.size();j++){
            if(rules[i].body.contentModifierHTTP[j]=="http_method"){
                if(methodString.find(rules[i].body.content[j])!=string::npos){
                	contentMatched[j]=true;
                }
            }else if (rules[i].body.contentModifierHTTP[j]=="http_uri"||rules[i].body.contentModifierHTTP[j]=="http_raw_uri"){
            	if(uriString.find(rules[i].body.content[j])!=string::npos){
            		contentMatched[j]=true;
            	}
            }else if (rules[i].body.contentModifierHTTP[j]=="http_stat_msg"){
            	if(statusMsgString.find(rules[i].body.content[j])!=string::npos){
            		contentMatched[j]=true;
            	}
            }else if (rules[i].body.contentModifierHTTP[j]=="http_stat_code"){
            	if(statusCodeString.find(rules[i].body.content[j])!=string::npos){
            		contentMatched[j]=true;
            	}
            }else{
                THROWEXCEPTION("Unknown or unexpected contentModifierHttp (or not yet implemented)");
            }
        }
        //if all contents match for this rule, write alert
        writeAlertBool=true;
        for(k=0;k<rules[i].body.content.size();k++){
        	if(contentMatched[k]==false){
        		writeAlertBool=false;
        		break;
        	}
        }
        if(writeAlertBool){
        	alertCounter++;
            writeAlert(&rules[i].body.sid, &rules[i].body.msg,sourceIPData,sourceIPType,
             destinationIPData,destinationIPType,
             sourcePortData,sourcePortType,
			 destinationPortData,destinationPortType,
			 startData,startType
            );
        }
    }//for loop through rules vector

    //not hand over record but remove references to it
	//record->removeReference();

	//hand record to next module
	send(record);
}

/**
* called if flow triggers alert.
* it writes alert + info to alertFile
*/
void IpfixIds::writeAlert(string* sid, string* msg, IpfixRecord::Data* srcIPData, InformationElement::IeInfo srcIPType,
                        IpfixRecord::Data* dstIPData,InformationElement::IeInfo dstIPType,
                        IpfixRecord::Data* srcPortData, InformationElement::IeInfo srcPortType,
                        IpfixRecord::Data* dstPortData,InformationElement::IeInfo dstPortType,
						IpfixRecord::Data* startData,InformationElement::IeInfo startType
						){
    fprintf(alertFile,"**ALERT**\n");
    fprintf(alertFile,"by rule(sid):\t%s\n",sid->c_str());
    fprintf(alertFile,"msg:\t\t%s\n",msg->c_str());
    fprintf(alertFile,"source:\t\t");
    printer.printIPv4(srcIPType,srcIPData);
    fprintf(alertFile,":");
    printer.printPort(srcPortType,srcPortData);
    fprintf(alertFile,"\ndestination:\t");
    printer.printIPv4(dstIPType,dstIPData);
    fprintf(alertFile,":");
    printer.printPort(dstPortType,dstPortData);
    fprintf(alertFile,"\nflow start:\t");
	printTimeSeconds(startData);
    fprintf(alertFile,"\n\n");


}

/**
 * helper function to print flow*NanoSeconds
 */
void IpfixIds::printTimeSeconds(IpfixRecord::Data* startData){
	timeval t;
	uint64_t hbnum;
    //printer.printLocaltime(startType,startData);
	hbnum = ntohll(*(uint64_t*)startData);
	if (hbnum>0) {
		t = timentp64(*((ntp64*)(&hbnum)));
		fprintf(alertFile, "%u.%06d seconds", (int32_t)t.tv_sec, (int32_t)t.tv_usec);
	} else {
		fprintf(alertFile, "no value (only zeroes in field)");
	}
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
