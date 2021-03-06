/*
 * Vermont Configuration Subsystem
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

#include "IpfixIdsCfg.h"

IpfixIdsCfg::IpfixIdsCfg(XMLElement* elem)
	: CfgHelper<IpfixIds, IpfixIdsCfg>(elem, "ipfixIds")
{
    //preset variables with known content
    alertFileString="NULL";
    rulesFileString="NULL";
    printParsedRules=false;
    useNtopIEs=false;
    httpPorts="NULL";

	if (!elem)
		return;

	msg(MSG_INFO, "IpfixIds ParserCfg: Start reading ipfixIds section");
	XMLNode::XMLSet<XMLElement*> set = _elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin(); it != set.end(); it++) {
		XMLElement* e = *it;

		if (e->matches("alertfile")) {
			alertFileString = e->getFirstText();
        }else if (e->matches("rulesfile")) {
			rulesFileString = e->getFirstText();
        }else if (e->matches("httpports")) {
        	THROWEXCEPTION("IpfixIdsCfg: httpports not supported in this version"); //just remove this message and uncomment stuff in IpfixIds.cpp
        	httpPorts = e->getFirstText();
        }else if (e->matches("printparsedrules")) {
			if(e->getFirstText()=="1\0"){
                printParsedRules=true;
            }
        }else if (e->matches("usentopies")) {
			if(e->getFirstText()=="1\0"){
                useNtopIEs=true;
            }
        } else if (e->matches("next")) { // ignore next
            continue;
		} else {
			msg(MSG_FATAL, "Unknown IpfixIds config statement %s\n", e->getName().c_str());
			THROWEXCEPTION("Unkown IpfixIds %s. Only 'alertfile', 'rulesfile', 'httpports', 'printparsedrules', 'usentopies' and 'next' allowed.\n", e->getName().c_str());
			continue;
		}
	}
}

IpfixIdsCfg::~IpfixIdsCfg()
{
}

IpfixIdsCfg* IpfixIdsCfg::create(XMLElement* e)
{
	return new IpfixIdsCfg(e);
}

IpfixIds* IpfixIdsCfg::createInstance()
{
	instance = new IpfixIds(alertFileString,rulesFileString,httpPorts,printParsedRules,useNtopIEs);
	return instance;
}

bool IpfixIdsCfg::deriveFrom(IpfixIdsCfg* old)
{
	return true;
}

