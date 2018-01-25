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
bool httpPortsGiven;
//to be able to choose between IANA and ntop method type
static InformationElement::IeInfo methodTypeChoice;
static InformationElement::IeInfo uriTypeChoice;
//the printer does not like ntops time IE
bool printTime;
/**
 * Creates a new IpfixIds.
 * Do not forget to call @c startIpfixIds() to begin printing
 * @return handle to use when calling @c destroyIpfixIds()
 */
IpfixIds::IpfixIds(string alertFS, string rulesFS, string httpP, bool printParsedRules, bool useNtopIEs)
{
	alertCounter=0;
    lastTemplate = 0;
	string file = "";
	alertFile = stdout;
	string line;
	httpPortsGiven=false;
	printTime=true;

	//default type to do intrusion detection on is the IANA type
	methodTypeChoice=InformationElement::IeInfo(IPFIX_TYPEID_httpRequestMethod, 0);
	uriTypeChoice= InformationElement::IeInfo(IPFIX_TYPEID_httpRequestTarget, 0);

    SnortRuleParser ruleParser;

	//open alertfile for writing
	if (alertFS == "NULL") {
        THROWEXCEPTION("IpfixIds: no alertfile given, aborting!");
	}else{
		alertFile = fopen(alertFS.c_str(), "w");
		//also tell the printhelper to use alertfile to print and not stdout
		printer.changeFile(alertFile);
		if (!alertFile)
			THROWEXCEPTION("IpfixIds: error opening alertfile '%s': %s (%u)", alertFS.c_str(), strerror(errno), errno);
	}

	if (rulesFS == "NULL") {
        THROWEXCEPTION("IpfixIds: no rulesfile given, aborting!");
	}else{
        rulesFile = fopen(rulesFS.c_str(), "r");
		if (!rulesFile){
			THROWEXCEPTION("IpfixIds: error opening rulesfile '%s': %s (%u)", rulesFS.c_str(), strerror(errno), errno);
        }else{
            //just checkin' rule is opened again in the parser
            int ret = fclose(rulesFile);
            if (ret){
                THROWEXCEPTION("IpfixIds: error closing rulesfile '%s': %s (%u). This should not happen!!!", rulesFS.c_str(), strerror(errno), errno);
            }
        }
	}

	//check httpPorts
	if (httpP == "NULL") {
		msg(MSG_INFO, "IpfixIds: No http ports given, ignoring $HTTP_PORTS directive in rules");
	}else{
		if(httpP==""){
			msg(MSG_INFO, "IpfixIds: No http ports given, ignoring $HTTP_PORTS directive in rules");
		}else{
			//reserve 100, shouldnt be more normally
			httpPorts.reserve(100);
			parsePorts(&httpP);
			httpPortsGiven=true;
		}
	}

	if(useNtopIEs){
		printTime=false;
		methodTypeChoice=InformationElement::IeInfo(IPFIX_ETYPEID_ntopHttpMethod, IPFIX_PEN_ntop, 0);
		uriTypeChoice= InformationElement::IeInfo(IPFIX_ETYPEID_ntopHttpUri, IPFIX_PEN_ntop, 0);
	}

    //be nice and tell people what the configuration is
    msg(MSG_INFO, "IpfixIds: started with following parameters:");
    msg(MSG_INFO, "  - Alertfile = %s", alertFS.c_str());
    msg(MSG_INFO, "  - Rulesfile = %s", rulesFS.c_str());
    if(useNtopIEs){
    	msg(MSG_INFO, "  - Configured to do intrusion detection on Ntops enterprise specific IEs");
    }else{
    	msg(MSG_INFO, "  - Configured to do intrusion detection on IANA IEs");
    }
    msg(MSG_INFO, "IpfixIds: starting to parse rulesfile");
    rules=ruleParser.parseMe(rulesFS.c_str());
    if(rules.size()>0){
        msg(MSG_DIALOG, "IpfixIds: %d rules parsed successfully",rules.size());
    }else{
        THROWEXCEPTION("IpfixIds: 0 rules parsed from rulesfile %s. Does this file contain properly formatted Snort rules?",rulesFS.c_str());
    }

    //do basic plausibility test, if this fails than there is a fault in the parser
    for(unsigned long i=0;i<rules.size();i++){
            ruleParser.compareVectorSizes(&rules[i]);
    }

    if(printParsedRules){
        fprintf(stdout,"------------------------------------------------------\n");
        fprintf(stdout,"IpfixIds: The following rules have been parsed from rulesfile %s\n", rulesFS.c_str());
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
		THROWEXCEPTION("IpfixIds: error closing alert file '%s': %s (%u)", strerror(errno), errno);
    }
}


/**
 * called on reception of Ipfix record
 */
void IpfixIds::onDataRecord(IpfixDataRecord* record)
{

	unsigned long j;
	unsigned long k;
	unsigned long l;
	bool writeAlertBool;
	bool portMatched;
	long portRule;
	long flowSrcPort;
	long flowDstPort;
	//end pointer for strtol operations
	char* end;

	string methodString;
	string uriString;
	string statusMsgString;
	string statusCodeString;

	IpfixRecord::Data* sourceIPData;
	IpfixRecord::Data* destinationIPData;
	IpfixRecord::Data* sourcePortData;
	IpfixRecord::Data* destinationPortData;
	IpfixRecord::Data* startData;
	IpfixRecord::Data* hostData;

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
        if (record->templateInfo->fieldInfo[i].type == methodTypeChoice) {
			 methodString= std::string((const char*)(record->data + record->templateInfo->fieldInfo[i].offset));
			 methodType=record->templateInfo->fieldInfo[i].type;
	}
        if (record->templateInfo->fieldInfo[i].type == uriTypeChoice) {
			uriString = std::string((const char*)(record->data + record->templateInfo->fieldInfo[i].offset));
			uriType=record->templateInfo->fieldInfo[i].type;
        }
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpStatusCode, 0)) {
			statusCodeString = std::string((const char*)(record->data + record->templateInfo->fieldInfo[i].offset));
			statusCodeType=record->templateInfo->fieldInfo[i].type;
        }
        //TODO convert also this type to IANA registered type
        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_ETYPEID_httpStatusPhrase, 0)) {
            statusMsgString = std::string((const char*)record->data + record->templateInfo->fieldInfo[i].offset);
            statusMsgType=record->templateInfo->fieldInfo[i].type;
        }
//        if (record->templateInfo->fieldInfo[i].type == InformationElement::IeInfo(IPFIX_TYPEID_httpRequestHost, 0)) {
//		   hostData = (record->data + record->templateInfo->fieldInfo[i].offset);
//		   hostType=record->templateInfo->fieldInfo[i].type;
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
    //BEWARE: there are gotos that break this loop
    for(l=0;l<rules.size();l++){
    	bool contentMatched[rules[l].body.content.size()]={0};
    	//check ports if necessary, source direction
        //TODO: implement address direction checks
//    	if(httpPortsGiven){
//        	flowSrcPort=getFlowPort(sourcePortType,sourcePortData);
//        	flowDstPort=getFlowPort(destinationPortType,destinationPortData);
//			if(rules[l].header.fromPort!="any"){
//				if(rules[l].header.fromPort=="$HTTP_PORTS"){
//					portMatched=false;
//					for(int i=0;i<httpPorts.size();i++){
//						//go through configuration defined httpPorts and compare
//						if(httpPorts.at(i)==flowSrcPort){
//							portMatched=true;
//							break;
//						}
//					}
//					if(!portMatched){
//						goto skipRule;
//					}
//				}else {//port must be a single number
//					portRule=strtol(rules[l].header.fromPort.c_str(),&end,10);
//					if(portRule==0){
//						msg(MSG_INFO,"Invalid rule (%s), it does not contain a valid source port definition (a number, '$HTTP_PORTS' or 'any')",rules[l].body.sid.c_str());
//						goto skipRule;
//					}else if(portRule!=flowDstPort){
//						goto skipRule;
//					}//if single port number matches, continue with rule
//				}
//			}
//			//same port check for destination direction
//			if(rules[l].header.toPort!="any"){
//				if(rules[l].header.toPort=="$HTTP_PORTS"){
//					portMatched=false;
//					for(int i=0;i<httpPorts.size();i++){
//						//go through configuration defined httpPorts and compare
//						if(httpPorts.at(i)==flowDstPort){
//							portMatched=true;
//							break;
//						}
//					}
//					if(!portMatched){
//						goto skipRule;
//					}
//				}else {//port must be a single number
//					portRule=strtol(rules[l].header.toPort.c_str(),&end,10);
//					if(portRule==0){
//						msg(MSG_INFO,"Invalid rule (%s), it does not contain a valid destination port definition (a number, '$HTTP_PORTS' or 'any')",rules[l].body.sid.c_str());
//						goto skipRule;
//					}else if(portRule!=flowDstPort){
//						goto skipRule;
//					}
//					//if single port number matches, continue with rule
//				}
//			}
//    	}

    	//
    	//This is the performance hungry loop. Any improvements here have massive impact on throughput performance
    	//
        for(j=0;j<rules[l].body.content.size();j++){
        //contentModifier vector MUST have same size than content vector
        	if(rules[l].body.contentNocase[j]){//case insensitive search
        		switch(rules[l].body.contentModifierHTTP[j]){
        			//TODO: its probably faster to encode method to something like int to avoid string comparison
					case 1:{//http_method
						if(strcasestr(methodString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							//skip the rest of the rule if content search is negative, this avoids expensive useless searches
							goto skipRule;
						}
					}
					case 2:	//http_uri
					case 3:{//http_raw_uri
						if(strcasestr(uriString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					//TODO: check if this keyword is present in rules and possibly leave this check away if not
					case 4:{//http_stat_msg
						if(strcasestr(statusMsgString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					//TODO: check if this keyword is present in rules and possibly leave this check away if not
					//TODO:try encoding stat code to int and see if its faster (useless because never used in current ruleset)
					case 5:{//http_stat_code
						if(strcasestr(statusCodeString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					default:{
						THROWEXCEPTION("IpfixIds: Unknown or unexpected contentModifierHttp: %s (or not yet implemented) in rule: %s",statusCodeString.c_str(),rules[l].body.sid.c_str());
					}
        		}
        	}else{//case sensitive search
        		switch(rules[l].body.contentModifierHTTP[j]){
					//TODO: its probably faster to encode method to something like int to avoid string comparison
					case 1:{//http_method
						if(strstr(methodString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							//skip the rest of the rule if content search is negative, this avoids expensive useless searches
							goto skipRule;
						}
					}
					case 2:	//http_uri
					case 3:{//http_raw_uri
						if(strstr(uriString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					case 4:{//http_stat_msg
						if(strstr(statusMsgString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					//TODO:try encoding stat code to int and see if its faster (useless because almost never used in rules)
					case 5:{//http_stat_code
						if(strstr(statusCodeString.c_str(),rules[l].body.content[j].c_str())!=NULL){
							if(rules[l].body.negatedContent[j]){
								contentMatched[j]=false;
							}else{
								contentMatched[j]=true;
							}
							break;
						}else{
							goto skipRule;
						}
					}
					default:{
						THROWEXCEPTION("IpfixIds: Unknown or unexpected contentModifierHttp (or not yet implemented)");
					}
				}
        	}
        }
        //if all contents match for this rule, write alert
        writeAlertBool=true;
        for(k=0;k<rules[l].body.content.size();k++){
        	if(contentMatched[k]==false){
        		writeAlertBool=false;
        		break;
        	}
        }

        if(writeAlertBool){
        	alertCounter++;
            writeAlert(&rules[l].body.sid, &rules[l].body.msg,sourceIPData,sourceIPType,
             destinationIPData,destinationIPType,
             sourcePortData,sourcePortType,
			 destinationPortData,destinationPortType,
			 startData,startType
            );
        }
        //jump here if a content match was false, so we save the time to do other content matches
        skipRule:;
    }//for loop through rules vector

    /*not hand over record but remove references to it*/
	//record->removeReference();
	/*hand record to next module*/
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
    if(printTime){
	printTimeSeconds(startData);
	}else{
	fprintf(alertFile,"cannot handle Ntops time format\t");
	}
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
 * expects a comma separated list of ints and puts them in an array of ints
 */
void IpfixIds::parsePorts(string* httpPortsString){
    std::size_t startPosition;
    std::size_t endPosition;
    long int port;
    endPosition=httpPortsString->find(",");
    while(endPosition!=std::string::npos){
    	port=strtol(httpPortsString->substr(0,endPosition).c_str(),NULL,10);
    	if(port==0L){
    		THROWEXCEPTION("IpfixIds: http Port list is not a comma separated list of numbers: %s (%u)", strerror(errno), errno);
    	}
    	httpPorts.push_back(port);
    	httpPortsString->erase(0,endPosition+1);
    	endPosition=httpPortsString->find(",");
    }
    //if no colon is found there should only be one port (or none but this has already been excluded before)
    port=strtol(httpPortsString->c_str(),NULL,10);
		if(port==0L){
			THROWEXCEPTION("IpfixIds: http Port list is not a comma separated list of numbers: %s (%u)", strerror(errno), errno);
		}
    httpPorts.push_back(port);
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

long IpfixIds::getFlowPort(InformationElement::IeInfo type, IpfixRecord::Data* data) {
	if (type.length == 0) {
		THROWEXCEPTION("IpfixIds: Flow with zero-length Port");
	}
	if (type.length == 2) {
		int port = ((uint16_t)data[0] << 8)+data[1];
		return port;
	}
//	if ((type.length >= 4) && ((type.length % 4) == 0)) {
//		int i;
//		for (i = 0; i < type.length; i+=4) {
//			int starti = ((uint16_t)data[i+0] << 8)+data[i+1];
//			int endi = ((uint16_t)data[i+2] << 8)+data[i+3];
//			if (i > 0) fprintf(fh, ",");
//			if (starti != endi) {
//				fprintf(fh, "%u:%u", starti, endi);
//			} else {
//				fprintf(fh, "%u", starti);
//			}
//		}
//		return;
//	}
	THROWEXCEPTION("Port with length %u unparseable", type.length);
}
