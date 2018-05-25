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
#include "core/Source.h"
#include "modules/ipfix/IpfixRecord.hpp"
#include "modules/ipfix/IpfixRecordDestination.h"
#include "modules/ipfix/IpfixPrinter.hpp"
//in contrast to std::regex, boost::regex supports lookbehind.
#include <boost/regex.hpp>

/**
 * IPFIX Intrusion Detection System Module
 *
 * This module takes as input ipfix flows and signature files and checks the flows against the signatures. If a signature matches an alert is written to the given alertfile.
 */
class IpfixIds : public Module, public IpfixRecordDestination, public Source<IpfixRecord*>
{
	public:
		IpfixIds(string alertFS,string rulesFSg, string httpP,bool printParsedRules,bool useNtopIEs);
		~IpfixIds();

		virtual void onDataRecord(IpfixDataRecord* record);
		virtual void onTemplate(IpfixTemplateRecord* record);
		virtual void onTemplateDestruction(IpfixTemplateDestructionRecord* record);

	protected:
		void* lastTemplate;
		FILE* alertFile;
		FILE* rulesFile;
		std::vector<long> httpPorts;
        std::vector<SnortRuleParser::snortRule> rules;
		bool printParsedRules;
		bool useNtopIEs;

	private:
		PrintHelpers printer;
		void parsePorts(string* ports);
		void printTimeSeconds(IpfixRecord::Data* startData);
		void printPayload(InformationElement::IeInfo type, IpfixRecord::Data* data, bool showOmittedZeroBytes,FILE* file);
		void printIPv4(InformationElement::IeInfo type, IpfixRecord::Data* data,FILE* file);
		void writeAlert(string* sid, string* msg, IpfixRecord::Data* srcIPData, InformationElement::IeInfo srcIPType,
                        IpfixRecord::Data* dstIPData,InformationElement::IeInfo dstIPType,
                        IpfixRecord::Data* srcPortData, InformationElement::IeInfo srcPortType,
                        IpfixRecord::Data* dstPortData,InformationElement::IeInfo dstPortType,
						IpfixRecord::Data* startData,InformationElement::IeInfo startType
		);
		long getFlowPort(InformationElement::IeInfo type, IpfixRecord::Data* data);

};

#endif
