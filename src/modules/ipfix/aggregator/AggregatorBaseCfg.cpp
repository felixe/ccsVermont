/*
 * Vermont Configuration Subsystem
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

#include "AggregatorBaseCfg.h"
#include "Rule.hpp"
#include "Rules.hpp"
#include "core/XMLElement.h"
#include "core/InfoElementCfg.h"

AggregatorBaseCfg::AggregatorBaseCfg(XMLElement* elem)
	: CfgBase(elem), pollInterval(0)
{
	if (!elem)
		return;

	rules = new Rules;
	htableBits = HT_DEFAULT_BITSIZE;

	XMLNode::XMLSet<XMLElement*> set = elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin();
	     it != set.end();
	     it++) {
		XMLElement* e = *it;
		if (e->matches("rule")) {
			Rule* r = readRule(e);
			if (r)
				rules->rule[rules->count++] = r;
		} else if (e->matches("expiration")) {
			// get the time values or set them to '0' if they are not specified
			maxBufferTime = getTimeInUnit("activeTimeout", SEC, 0, e);
			minBufferTime = getTimeInUnit("inactiveTimeout", SEC, 0, e);
			if (!maxBufferTime) THROWEXCEPTION("active timeout not set in configuration for aggregator");
			if (!minBufferTime) THROWEXCEPTION("inactive timeout not set in configuration for aggregator");
		} else if (e->matches("pollInterval")) {
			pollInterval = getTimeInUnit("pollInterval", mSEC, AGG_DEFAULT_POLLING_TIME);
		} else if (e->matches("hashtableBits")) {
			htableBits = getInt("hashtableBits", HT_DEFAULT_BITSIZE);
		} else if (e->matches("next")) { // ignore next
		} else {
			msg(MSG_FATAL, "Unkown Aggregator config entry %s\n", e->getName().c_str());
		}
	}
}

AggregatorBaseCfg::~AggregatorBaseCfg()
{
}

Rule* AggregatorBaseCfg::readRule(XMLElement* elem) {
	// nonflowkey -> aggregate
	// flowkey -> keep

	Rule* rule = new Rule();
	XMLNode::XMLSet<XMLElement*> set = elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin();
	     it != set.end();
	     it++) {
		XMLElement* e = *it;

		if (e->matches("templateId")) {
			rule->id = getInt("templateId", 0, e);
		} else if (e->matches("preceding")) {
			rule->preceding = getInt("preceding", 0, e);
		} else if (e->matches("biflowAggregation")) {
			rule->biflowAggregation = getInt("biflowAggregation", 0, e);
		} else if (e->matches("httpAggregation")) {
			rule->httpAggregation = getInt("httpAggregation", 0, e);
		} else if (e->matches("httpSkipHeader")) {
            rule->httpSkipHeader = getInt("httpSkipHeader", 0, e);
        } else if (e->matches("httpMsgBufferSize")) {
            rule->httpMsgBufferSize = getUInt32("httpMsgBufferSize", 0, e);
        } else if (e->matches("tcpMonitor")) {
            XMLNode::XMLSet<XMLElement*> tcpMonitorSet = e->getElementChildren();
            for (XMLNode::XMLSet<XMLElement*>::iterator tit = tcpMonitorSet.begin();
                    tit != tcpMonitorSet.end();
                    tit++) {
                XMLElement* te = *tit;
                if (te->matches("attemptedConnectionTimeout")) {
                    rule->tcpmonTimeoutAttempt = getTimeInUnit("attemptedConnectionTimeout", mSEC, 0, e);
                } else if (te->matches("establishedConnectionTimeout")) {
                    rule->tcpmonTimeoutEstablished = getTimeInUnit("establishedConnectionTimeout", mSEC, 0, e);
                } else if (te->matches("closedConnectionTimeout")) {
                    rule->tcpmonTimeoutClosed = getTimeInUnit("closedConnectionTimeout", mSEC, 0, e);
                } else if (te->matches("connectionBufferSize")) {
                    rule->tcpmonBufferSize = getUInt32("connectionBufferSize", 0, te);
                } else if (te->matches("usePCAPTimestamps")) {
                    rule->tcpmonPCAPTimestamps = getBool("usePCAPTimestamps", true, te);
                }
            }
        } else if (e->matches("flowKey")) {
			Rule::Field* ruleField = readFlowKeyRule(e);
			if (ruleField)
				rule->field[rule->fieldCount++] = ruleField;
		} else if (e->matches("nonFlowKey")) {
			Rule::Field* ruleField = readNonFlowKeyRule(e);
			if (ruleField)
				rule->field[rule->fieldCount++] = ruleField;
		} else {
			THROWEXCEPTION("Unknown rule %s in Aggregator found", e->getName().c_str());
		}
	}

	// we found no rules, so do cleanup
	if (rule->fieldCount == 0) {
		delete rule;
		rule = NULL;
	}

	if (rule->httpAggregation) {
	    bool front = false;
	    bool rev = false;
        for (int i;i<rule->fieldCount;i++) {
          if (rule->field[i]->type == InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont))
              front = true;
          else if (rule->field[i]->type == InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse))
              rev = true;
        }
        if (!(front && rev))
            THROWEXCEPTION("HTTP aggregation requires the fields frontPayload and revFrontPayload to be set in the configuration!");
	}
    // biflowAggregation has to be enabled for httpAggregation
    if (rule->httpAggregation && !rule->biflowAggregation) {
        rule->biflowAggregation = 1;
        msg(MSG_DIALOG, "Implicitly enabling biflowAggregation, since httpAggregation only works in conjunction with biflowAggregation.");
    }

    if (!rule->httpAggregation && (rule->tcpmonTimeoutAttempt || rule->tcpmonTimeoutEstablished || rule->tcpmonTimeoutClosed || rule->tcpmonBufferSize || rule->httpSkipHeader || rule->httpMsgBufferSize)) {
        msg(MSG_INFO, "The options attemptedConnectionTimeout, establishedConnectionTimeout, closedConnectionTimeout, tcpmonBufferSize, httpSkipHeader and httpaggBufferSize have no impact if httpAggregation is disabled.");
    }

	// exclude coexistence of patterns and biflow aggregation
	if(rule->biflowAggregation) {
		for(int i=0; i < rule->fieldCount; i++) {
			if(rule->field[i]->pattern)
				msg(MSG_ERROR, "AggregatorBaseCfg: Match pattern for id=%d ignored because biflow aggregation is enabled.", rule->field[i]->type.id);
				free(rule->field[i]->pattern);
				rule->field[i]->pattern = NULL;
		}
	}

	return rule;
}

Rule::Field* AggregatorBaseCfg::readNonFlowKeyRule(XMLElement* e)
{
	Rule::Field* ruleField = new Rule::Field();
	InfoElementCfg ie(e);

	if (!ie.isKnownIE())
		THROWEXCEPTION("Unsupported non-key field %s (id=%u, enterprise=%lu).", (ie.getIeName()).c_str(), ie.getIeId(), ie.getEnterpriseNumber());

	ruleField->modifier = Rule::Field::AGGREGATE;
	ruleField->type.id = ie.getIeId();
	ruleField->type.enterprise = ie.getEnterpriseNumber();
	ruleField->type.length = ie.getIeLength();

	if ((ruleField->type == InformationElement::IeInfo(IPFIX_TYPEID_sourceIPv4Address, 0)) ||
			(ruleField->type == InformationElement::IeInfo(IPFIX_TYPEID_destinationIPv4Address, 0))) {
		ruleField->type.length++; // for additional mask field
	}

	// HTTP aggregation requires the IPFIX_ETYPEID_frontPayload field to work.
	// However, it might not be desired to export payload in every case, and thus
	// a payload length of 0 bytes should be allowed.
//	if (ruleField->type == InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont) ||
//			ruleField->type == InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)) {
//		if (ruleField->type.length<5)
//			THROWEXCEPTION("type %s must have at least size 5!", ipfix_id_lookup(ruleField->type.id, ruleField->type.enterprise)->name);
//	}

	return ruleField;
}

Rule::Field* AggregatorBaseCfg::readFlowKeyRule(XMLElement* e) {
	Rule::Field* ruleField = new Rule::Field();
	InfoElementCfg ie(e);

	if (!ie.isKnownIE())
		THROWEXCEPTION("Unknown flow key field %s (id=%u, enterprise=%u).", (ie.getIeName()).c_str(), ie.getIeId(), ie.getEnterpriseNumber());

	try {   // TODO: not sure why we don't abort here; just use the same code as before restructuring
		// I added a delete ruleField in the catch, perhaps thats why it was needed?

		// parse modifier
		if (ie.getModifier().empty() || (ie.getModifier() == "keep")) {
			ruleField->modifier = Rule::Field::KEEP;
		} else if (ie.getModifier() == "discard") {
			ruleField->modifier = Rule::Field::DISCARD;
		} else {
			ruleField->modifier = (Rule::Field::Modifier)((int)Rule::Field::MASK_START + atoi(ie.getModifier().c_str() + 5));
		}

		ruleField->type.id = ie.getIeId();
		ruleField->type.enterprise = ie.getEnterpriseNumber();
		ruleField->type.length = ie.getIeLength();

		if ((ruleField->type.id == IPFIX_TYPEID_sourceIPv4Address) || (ruleField->type.id == IPFIX_TYPEID_destinationIPv4Address)) {
			ruleField->type.length++; // for additional mask field
		}

		if (!ie.getMatch().empty()) {
			// TODO: we need to copy the string because parseProtoPattern and
			//  parseIPv4Pattern violate the original string
			char* tmp = new char[ie.getMatch().length() + 1];
			strcpy(tmp, ie.getMatch().c_str());
			ruleField->pattern = NULL;

			switch (ruleField->type.id) {
			case IPFIX_TYPEID_protocolIdentifier:
				if (parseProtoPattern(tmp, &ruleField->pattern, &ruleField->type.length) != 0) {
					msg(MSG_ERROR, "Bad protocol pattern \"%s\"", tmp);
					delete [] tmp;
					throw std::exception();
				}
				break;
			case IPFIX_TYPEID_sourceIPv4Address:
			case IPFIX_TYPEID_destinationIPv4Address:
				if (parseIPv4Pattern(tmp, &ruleField->pattern, &ruleField->type.length) != 0) {
					msg(MSG_ERROR, "Bad IPv4 pattern \"%s\"", tmp);
					delete [] tmp;
					throw std::exception();
				}
				break;
			case IPFIX_TYPEID_sourceTransportPort:
			case IPFIX_TYPEID_udpSourcePort:
			case IPFIX_TYPEID_tcpSourcePort:
			case IPFIX_TYPEID_destinationTransportPort:
			case IPFIX_TYPEID_udpDestinationPort:
			case IPFIX_TYPEID_tcpDestinationPort:
				if (parsePortPattern(tmp, &ruleField->pattern, &ruleField->type.length) != 0) {
					msg(MSG_ERROR, "Bad PortRanges pattern \"%s\"", tmp);
					delete [] tmp;
					throw std::exception();
				}
				break;
			case IPFIX_TYPEID_tcpControlBits:
				if (parseTcpFlags(tmp, &ruleField->pattern, &ruleField->type.length) != 0) {
					msg(MSG_ERROR, "Bad TCP flags pattern \"%s\"", tmp);
					delete [] tmp;
					throw std::exception();
				}
				break;

			default:
				msg(MSG_ERROR, "Fields of type \"%s\" cannot be matched against a pattern %s", "", tmp);
				delete tmp;
				throw std::exception();
				break;
			}
			delete [] tmp;
		}
	} catch (std::exception e) {
		delete ruleField;
		ruleField = NULL;
	}


	return ruleField;
}
