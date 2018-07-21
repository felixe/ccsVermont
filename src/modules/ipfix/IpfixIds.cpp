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

int   alertCounter;
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
IpfixIds::IpfixIds(string alertFS, string rulesFS, string httpP, bool printParsedRules, bool useNtopIEs, string stringThreads)
{
	alertCounter=0;
    lastTemplate = 0;
	string file = "";
	string line;
	httpPortsGiven=false;
	printTime=true;
	queueNum=0;
	threadsWork=true;

	//default type to do intrusion detection on is the IANA type
	methodTypeChoice=InformationElement::IeInfo(IPFIX_TYPEID_httpRequestMethod, 0);
	uriTypeChoice= InformationElement::IeInfo(IPFIX_TYPEID_httpRequestTarget, 0);

    SnortRuleParser ruleParser;

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

	if(stringThreads=="NULL"|stringThreads==""){
		msg(MSG_INFO, "IpfixIds: No number for parallel threads given, using only single thread for pattern matching");
		threads=1;
	}else{
		try
		{
			threads=std::stoi(stringThreads);
		}catch (std::invalid_argument& e){
			THROWEXCEPTION("IpfixIds: \"%s\" seems to be an invalid argument for the 'threads' config directive ", stringThreads.c_str());
		}catch (std::out_of_range& e){
			THROWEXCEPTION("IpfixIds: really? you want %s threads? screw that! ", stringThreads.c_str());
		}
	}

	//start patternMatching threads:
	//threads starten
	threadsWork=1;

	//loop to fill all thread related vectors
	for(int i=0; i<threads; i++){
		threadIsFinished.push_back(false);
		//default to stdout, is changed below to actual file
		alertFile.push_back(stdout);
		//create corresponding queue
		//this could actually have an influence on performance, but 10mio pointers should be enough for quite some while
		std::queue <IpfixDataRecord*> placeHolderQueue;
		flowQueues.push_back(placeHolderQueue);
		std::thread placeHolderThread(&IpfixIds::patternMatching,this,i);
		freds.push_back(move(placeHolderThread));
		freds.back().detach();
	}

	//open alertfile for writing
	if (alertFS == "NULL") {
        THROWEXCEPTION("IpfixIds: no alertfile given, aborting!");
	}else{
		for(int i=0; i<threads; i++){
			alertFile.at(i) = fopen((alertFS+std::to_string(i)).c_str(), "w");
			//we are telling the print helper in every thread to use the appropriate file.
			if (!alertFile.at(i))
				THROWEXCEPTION("IpfixIds: error opening alertfile '%s': %s (%u)", alertFS.c_str(), strerror(errno), errno);
		}
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
    msg(MSG_INFO, "  - Configured to use %d threads for pattern matching", threads);
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
    	msg(MSG_INFO,"------------------------------------------------------");
    	msg(MSG_INFO,"IpfixIds: The following rules have been parsed from rulesfile %s", rulesFS.c_str());
    	msg(MSG_INFO,"------------------------------------------------------");
        for(unsigned long i=0;i<rules.size();i++){
            ruleParser.printSnortRule(&rules[i]);
        }
        msg(MSG_INFO,"------------------------------------------------------");
    }
}

/**
 * Frees memory used by an IpfixIds
 */
IpfixIds::~IpfixIds()
{
	bool finish=false;
	//we need to tell threads to shutdown
	threadsWork=false;
	msg(MSG_INFO, "IpfixIds: Told pattern matching threads to empty queues and finish");
	//since we detach the threads, they are not joinable anymore
	//and they should stop if threadsWork is false.
	//thus, we also need to wait for threads to finish queues
	while(!finish){
		usleep(100000);//wait a tenth second
		finish=true;
		for(int i=0;i<threads;i++){
			if(threadIsFinished.at(i)==false){
				finish=false;
			}
		}
	}
	msg(MSG_DEBUG, "IpfixIds:Threads finished");
	msg(MSG_DIALOG,"IpfixIds: If more than one thread is used for IDS pattern matching than the following counter might be inaccurate");
	msg(MSG_DIALOG,"IpfixIds: %d alerts triggered",alertCounter);
	//close alertfiles before shutdown
	for(int i=0; i<threads; i++){
		int ret = fclose(alertFile.at(i));
			if (ret){
				THROWEXCEPTION("IpfixIds: error closing alert file '%s': %s (%u)", strerror(errno), errno);
		    }
	}
}

/**
 * This is where all the IDS pattern matching of rules vs. flows takes place.
 * This function is executed by threads who work on queues of incoming flows.
 * Every thread has its own queue to avoid locking operations.
 * threadNum is used to identify the right queue.
 */
void IpfixIds::patternMatching(int threadNum){
	unsigned long j,k,l,m,flowCounter=0;
	bool writeAlertBool;
	bool portMatched;
	long portRule;
	long flowSrcPort;
	long flowDstPort;
	//end pointer for strtol operations
	char* end;
	//every thread has own printer instance and writes to own alert file to avoid racing conditions (and mutex operations)
	PrintHelpers* threadPrinter=new PrintHelpers();
    //threadPrinter->changeFile(alertFile.at(threadNum));

	string methodString;
	string uriString;
	string uriStringPcre;
	string statusMsgString;
	string statusCodeString;
	IpfixDataRecord* record;

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

    while(true){
    	//avoid trying to read empty queue (->undefined behavior):
    	while(flowQueues.at(threadNum).empty()){
    		//TODO: what sleep time is the best performance-wise?
    		usleep(50);
    		//if queue is empty AND threadsWork is set to false we have to stop and goto printCounter
    		if(!threadsWork){
    			goto printCounter;
    		}
    	}
    	//FIFO style: insert with push, read front, remove with pop
    	record=flowQueues.at(threadNum).front();
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
			//contentMatched array must be all true for a rule match, here it is resetted
			bool contentMatched[rules[l].body.contentModifierHTTP.size()+rules[l].body.pcre.size()]={0};
			//check ports if necessary, source direction
			//TODO: implement address direction checks
			//TODO: if following port checks are uncommented check if it still fits structure
			//-->http port checks removed, check older commits (prior to 5.6.18)

			//This is the performance hungry loop. Any improvements here have massive impact on throughput performance
			for(j=0;j<rules[l].body.content.size();j++){
			//contentModifier vector MUST have same size than content vector
				if(rules[l].body.contentNocase[j]){//case insensitive search
					switch(rules[l].body.contentModifierHTTP[j]){
						case 1:{//http_method
							//if match
							if(strcasestr(methodString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						case 2:	//http_uri
						case 3:{//http_raw_uri
							if(strcasestr(uriString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						//TODO: check if this keyword is present in rules and possibly leave this check away if not
						case 4:{//http_stat_msg
							if(strcasestr(statusMsgString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						//TODO:try encoding stat code to int and see if its faster (useless because never used in current ruleset)
						case 5:{//http_stat_code
							if(strcasestr(statusCodeString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						default:{
							THROWEXCEPTION("IpfixIds: Unknown or unexpected contentModifierHttp: %s (or content with no HTTP modifier) in rule with sid: %s",statusCodeString.c_str(),rules[l].body.sid.c_str());
						}
					}
				}else{//case sensitive search
					switch(rules[l].body.contentModifierHTTP[j]){
						case 1:{//http_method
							if(strstr(methodString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						case 2:	//http_uri
						case 3:{//http_raw_uri
							if(strstr(uriString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						case 4:{//http_stat_msg
							if(strstr(statusMsgString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						//TODO:try encoding stat code to int and see if its faster (-->useless because almost never used in rules)
						case 5:{//http_stat_code
							if(strstr(statusCodeString.c_str(),rules[l].body.content[j].c_str())!=NULL){
								if(rules[l].body.negatedContent[j]){
									//skip the rest of the rule if content search is negative, this avoids expensive useless searches
									goto skipRule;
								}else{
									contentMatched[j]=true;
								}
								break;
							//if no match
							}else{
								if(rules[l].body.negatedContent[j]){
									contentMatched[j]=true;
								}else{
									goto skipRule;
								}
								break;
							}
						}
						default:{
							THROWEXCEPTION("IpfixIds: Unknown or unexpected contentModifierHttp: %s (or pcre with no HTTP modifier) in rule with sid: %s",statusCodeString.c_str(),rules[l].body.sid.c_str());
						}
					}
				}
			}

			//change whitespaces in uri for pcre search
			uriStringPcre=changeUriWs(uriString);
			//PCRE loop: Is skipped by the goto statements above if any of the above content patterns does not match.
			//As pcres are almost always the last statement in a rule this part should be reached very seldomly and thus have a minor impact on performance.
			for(m=0;m<rules[l].body.pcre.size();m++){
				try {//try to catch regex errors
					if(rules[l].body.pcreNocase[j]){//---> case insensitive regex search
						//regex_match is case sensitive by default, icase switches to case insensitive. default is perl, just to make sure.
						boost::regex ruleRegex(rules[l].body.pcre.at(m),boost::regex::perl|boost::regex::icase);
						//printf("###case ins. regex search. uri %s,regex %s\n",uriStringPcre.c_str(),rules[l].body.pcre.at(m).c_str());
						switch(rules[l].body.contentModifierHTTP[m+(rules[l].body.content.size())]){
							case 1:{//http_method
								if(regex_search(methodString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							//PROBLEM:the set of whitespace chars (\s) does not include URI whitespaces like +.
							case 2:	//http_uri
							case 3:{//http_raw_uri
								if(regex_search(uriStringPcre,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							case 4:{//http_stat_msg
								if(regex_search(statusMsgString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							case 5:{//http_stat_code
								if(regex_search(statusCodeString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							default:{
								THROWEXCEPTION("IpfixIds: Unknown or unexpected (HTTP) modifier for PCRE: %s (or not yet implemented) in rule with sid: %s",statusCodeString.c_str(),rules[l].body.sid.c_str());
							}
						}
					}else{//case sensitive pcre search
						//regex_search is case sensitive by default, icase switches to case insensitive.
						boost::regex ruleRegex(rules[l].body.pcre.at(m));
						switch(rules[l].body.contentModifierHTTP[m+(rules[l].body.content.size())]){
							case 1:{//http_method
								if(regex_search(methodString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							case 2:	//http_uri
							case 3:{//http_raw_uri
								if(regex_search(uriStringPcre,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							case 4:{//http_stat_msg
								if(regex_search(statusMsgString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							case 5:{//http_stat_code
								if(regex_search(statusCodeString,ruleRegex)){
									if(rules[l].body.negatedPcre[m]){
										//skip the rest of the rule if content search is negative, this avoids expensive useless searches
										goto skipRule;
									}else{
										contentMatched[m+(rules[l].body.content.size())]=true;
									}
								}else{
									if(rules[l].body.negatedPcre[m]){
										contentMatched[m+(rules[l].body.content.size())]=true;
									}else{
										goto skipRule;
									}
								}
								break;
							}
							default:{
								THROWEXCEPTION("IpfixIds: Unknown or unexpected (HTTP) modifier for PCRE: %s (or not yet implemented) in rule with sid: %s",statusCodeString.c_str(),rules[l].body.sid.c_str());
							}
						}
					}
				}catch (const boost::regex_error& e) {
					std::string msg;
					if(e.code()==boost::regex_constants::error_collate){
										msg="The expression contained an invalid collating element name";
									}
					if(e.code()==boost::regex_constants::error_ctype){
										msg="The expression contained an invalid character class name";
									}
					if(e.code()==boost::regex_constants::error_escape){
										msg="The expression contained an invalid escaped character, or a trailing escape";
									}
					if(e.code()==boost::regex_constants::error_backref){
										msg="TThe expression contained an invalid back reference";
									}
					if(e.code()==boost::regex_constants::error_brack){
										msg="The expression contained mismatched brackets";
									}
					if(e.code()==boost::regex_constants::error_paren){
										msg="The expression contained mismatched parentheses";
									}
					if(e.code()==boost::regex_constants::error_brace){
										msg="The expression contained mismatched braces";
									}
					if(e.code()==boost::regex_constants::error_badbrace){
										msg="The expression contained an invalid range between braces";
									}
					if(e.code()==boost::regex_constants::error_range){
										msg="The expression contained an invalid character range";
									}
					if(e.code()==boost::regex_constants::error_space){
										msg="There was insufficient memory to convert the expression info a finite state machine";
									}
					if(e.code()==boost::regex_constants::error_badrepeat){
										msg="The expression contained a repeat specifier (one of *?+{) that was not preceded by a valid regular expression";
									}
					if(e.code()==boost::regex_constants::error_complexity){
										msg="The complexity of an attempted match against a regular expression exceeded a pre-set level";
									}
					if(e.code()==boost::regex_constants::error_stack){
										msg="There was insufficient stack memory to determine whether the regular expression could match the specified character sequence";
									}
					if(e.code()==boost::regex_constants::error_bad_pattern){
										msg="Other, unspecified Error";
									}
					//e.code returns boost::regex_constants
					THROWEXCEPTION("IpfixIds: regex_error caught during detection on rule sid:%s, what: %s, code %d. Msg: %s\n",rules[l].body.sid.c_str(), e.what(), e.code(), msg.c_str());
				}
				catch (const boost::exception& e) {
					//ugly way to catch this specific expression, but for the love of god, I couldnt come up with something better
					string errMsg=boost::diagnostic_information(e);
					if(errMsg.find("The complexity of matching the regular expression exceeded predefined bounds")!=std::string::npos){
						//it is only detected in combination with a possibly hazardous text (haystack) to match against
						msg(MSG_DIALOG, "IpfixIds: Boost::regex detected RegEx pattern which might lead to very long pattern matching times. Simplify pattern, if possible. Rule sid:%s", rules[l].body.sid.c_str());
					}else{
						//rethrow exception if not caught by above.
						throw;
						//just to make sure
						THROWEXCEPTION("IpfixIds: BOOST EXCEPTION thrown\n");
					}
				}

			}//for loop
			//if all contents match for this rule, write alert
			//to check if everything BUT pcre stuff matched, simply only check the first |content.size()| number of elements.
			writeAlertBool=true;
			for(k=0;k<rules[l].body.contentModifierHTTP.size();k++){
				if(contentMatched[k]==false){
					writeAlertBool=false;
					break;
				}
			}

			if(writeAlertBool){
				alertCounter++;
				writeAlert(threadNum, &rules[l].body.sid, &rules[l].body.msg,sourceIPData,sourceIPType,
				 destinationIPData,destinationIPType,
				 sourcePortData,sourcePortType,
				 destinationPortData,destinationPortType,
				 startData,startType,threadPrinter
				);
			}
			//jump here if a content match was false, so we save the time to do other (useless) content matches
			skipRule:;
		}//for loop through rules vector

		//remove first and then pop or other way round?!?
		//FIFO style: insert with push, read front, remove with pop
		flowQueues.at(threadNum).pop();
		//send(record);
		//record->removeReference();
		flowCounter++;
		//TODO:do we have race conditions if threads use send(record); ? Maybe do that if above works stable
    }//while threadWork
    printCounter:;
    msg(MSG_DEBUG, "IpfixIds: Pattern Matching thread %d processed %d flows",threadNum,flowCounter);
    threadIsFinished.at(threadNum)=true;
}

/**
 * called on reception of Ipfix record
 */
void IpfixIds::onDataRecord(IpfixDataRecord* record)
{
	//all the record handling stuff is done in parallel in the patternMatching method, here we only prepare the records by putting the reference in the appropriate queue
	//distribute incoming flows on queues in round-robin fashion
	//FIFO style: insert with push, read front, remove with pop
	flowQueues.at(queueNum++).push(record);
	if(queueNum>=threads){
		queueNum=0;
	}
	//record reference is handled in patternMatching(..)
}

/**
* called if flow triggers alert.
* it writes alert + info to alertFile
*/
void IpfixIds::writeAlert(int threadNum, string* sid, string* msg, IpfixRecord::Data* srcIPData, InformationElement::IeInfo srcIPType,
                        IpfixRecord::Data* dstIPData,InformationElement::IeInfo dstIPType,
                        IpfixRecord::Data* srcPortData, InformationElement::IeInfo srcPortType,
                        IpfixRecord::Data* dstPortData,InformationElement::IeInfo dstPortType,
						IpfixRecord::Data* startData,InformationElement::IeInfo startType,
						PrintHelpers* printer){
	printer->changeFile(alertFile.at(threadNum));
    fprintf(alertFile.at(threadNum),"**ALERT**\n");
    fprintf(alertFile.at(threadNum),"by rule(sid):\t%s\n",sid->c_str());
    fprintf(alertFile.at(threadNum),"msg:\t\t%s\n",msg->c_str());
    fprintf(alertFile.at(threadNum),"source:\t\t");
    printer->printIPv4(srcIPType,srcIPData);
    fprintf(alertFile.at(threadNum),":");
    printer->printPort(srcPortType,srcPortData);
    fprintf(alertFile.at(threadNum),"\ndestination:\t");
    printer->printIPv4(dstIPType,dstIPData);
    fprintf(alertFile.at(threadNum),":");
    printer->printPort(dstPortType,dstPortData);
    fprintf(alertFile.at(threadNum),"\nflow start:\t");
    if(printTime){
	printTimeSeconds(threadNum, startData);
	}else{
	fprintf(alertFile.at(threadNum),"cannot handle Ntops time format\t");
	}
    fprintf(alertFile.at(threadNum),"\n\n");

}

/**
 * helper function to print flow*NanoSeconds
 */
void IpfixIds::printTimeSeconds(int threadNum, IpfixRecord::Data* startData){
	timeval t;
	uint64_t hbnum;
    //printer.printLocaltime(startType,startData);
	hbnum = ntohll(*(uint64_t*)startData);
	if (hbnum>0) {
		t = timentp64(*((ntp64*)(&hbnum)));
		fprintf(alertFile.at(threadNum), "%u.%06d seconds", (int32_t)t.tv_sec, (int32_t)t.tv_usec);
	} else {
		fprintf(alertFile.at(threadNum), "no value (only zeroes in field)");
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

/*
 * changes + an %20 sign to ' ' sign
 * Problem is that + and %20 represent a whitespace in uris, but pcres dont recognize it as whitespace.
 */
string IpfixIds::changeUriWs(string uri){
	int pos;
	while((pos=uri.find('+'))!=string::npos){
		uri.replace(pos,1," ");
	}
	while((pos=uri.find("%20"))!=string::npos){
		uri.replace(pos,3," ");
	}
	return uri;
}
