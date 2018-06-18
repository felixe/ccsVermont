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

#ifndef IPFIXIDS_H
#define IPFIXIDS_H


#include "../../common/SnortRuleParser.h"
#include "core/Module.h"
#include "modules/ipfix/IpfixRecord.hpp"
#include "modules/ipfix/IpfixRecordDestination.h"
#include "modules/ipfix/IpfixPrinter.hpp"
//in contrast to std::regex, boost::regex supports lookbehind.
#include <boost/regex.hpp>
#include <thread>

/**
 * IPFIX Intrusion Detection System Module
 *
 * This module takes as input ipfix flows and signature files and checks the flows against the signatures. If a signature matches an alert is written to the given alertfile.
 */
class IpfixIds : public Module, public IpfixRecordDestination, public Source<IpfixRecord*>
{
	public:
		IpfixIds(string alertFS,string rulesFSg, string httpP,bool printParsedRules,bool useNtopIEs, string threads);
		~IpfixIds();

		virtual void onDataRecord(IpfixDataRecord* record);
		virtual void onTemplate(IpfixTemplateRecord* record);
		virtual void onTemplateDestruction(IpfixTemplateDestructionRecord* record);

	protected:
		//why are all these protected and not private again?
		void* lastTemplate;
		FILE* rulesFile;
		std::vector<long> httpPorts;
        std::vector<SnortRuleParser::snortRule> rules;
		bool printParsedRules;
		bool useNtopIEs;

	private:
		int threads;
		bool threadsWork; //set to false if threads should stop
		//for parallel pattern matching
		int queueNum; //global round-robin counter to know where to put incoming flow
		vector <queue <IpfixDataRecord*>> flowQueues;
		vector <std::thread> freds;
		vector <FILE*> alertFile;//every thread is writing to own alertFile;
		vector <bool> threadIsFinished; //this is false and set to true if corresponding thread is finished


		void parsePorts(string* ports);
		void printTimeSeconds(int threadNum, IpfixRecord::Data* startData);
		void printPayload(InformationElement::IeInfo type, IpfixRecord::Data* data, bool showOmittedZeroBytes,FILE* file);
		void printIPv4(InformationElement::IeInfo type, IpfixRecord::Data* data,FILE* file);
		void writeAlert(int threadNum, string* sid, string* msg, IpfixRecord::Data* srcIPData, InformationElement::IeInfo srcIPType,
                        IpfixRecord::Data* dstIPData,InformationElement::IeInfo dstIPType,
                        IpfixRecord::Data* srcPortData, InformationElement::IeInfo srcPortType,
                        IpfixRecord::Data* dstPortData,InformationElement::IeInfo dstPortType,
						IpfixRecord::Data* startData,InformationElement::IeInfo startType,
						PrintHelpers* printer
		);
		long getFlowPort(InformationElement::IeInfo type, IpfixRecord::Data* data);
		void patternMatching(int threadNum);
		string changeUriWs(string uri);

};

#endif
