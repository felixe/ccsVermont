/*
 * OverlayProtocolFinder Configuration Subsystem
 * Copyright (C) 2012 Felix Erlacher
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

#include "OverlayProtocolFinderCfg.h"
#include "OverlayProtocols.hpp"

OverlayProtocolFinderCfg::OverlayProtocolFinderCfg(XMLElement* elem)
	: CfgHelper<OverlayProtocolFinder, OverlayProtocolFinderCfg>(elem, "overlayProtocolFinder")
{
	if (!elem){
			//msg(MSG_DIALOG, "no confing element found in oPF config");
			return;
		}
		XMLNode::XMLSet<XMLElement*> set = elem->getElementChildren();
		for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin();
		     it != set.end();
		     it++) {
			//Cfg* c;
			XMLElement* e = *it;

			if (e->matches("protocol")) {
				protocol=get("protocol",0);
			} else if (e->matches("next")) { // ignore next
				continue;
			} else {
				msg(MSG_FATAL, "Unkown parameter %s, only <protocol> supported\n", e->getName().c_str());
				THROWEXCEPTION("Unkown parameter %s, only <protocol> supported\n", e->getName().c_str());
				continue;
			}

			//subCfgs.push_back(c);
		}
}

OverlayProtocolFinderCfg::~OverlayProtocolFinderCfg()
{
}

OverlayProtocolFinderCfg* OverlayProtocolFinderCfg::create(XMLElement* elem)
{
	assert(elem);
	assert(elem->getName() == getName());
	return new OverlayProtocolFinderCfg(elem);
}

OverlayProtocolFinder* OverlayProtocolFinderCfg::createInstance()
{
	instance = new OverlayProtocolFinder(getRegex(protocol));
	return instance;
}

bool OverlayProtocolFinderCfg::deriveFrom(OverlayProtocolFinderCfg* old)
{
	return false;  // FIXME: implement it, to gain performance increase in reconnect
}


/**
 * returns the regex the overlayProtocolFinder has to look for
 */
std::string OverlayProtocolFinderCfg::getRegex(std::string prot)
{
	std::string regex=overlayProtocol_regex_lookup(prot);
	if(regex==""){
		if(prot==""){
			THROWEXCEPTION("No overlay protocol given");
		}else{
			THROWEXCEPTION("Unknown overlay protocol: %s",prot.c_str());
		}
	}
	return regex;
}


