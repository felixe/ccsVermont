/*
 * Vermont Configuration Subsystem
 * Copyright (C) 2017 Vermont Project
 * Author: Felix Erlacher
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


//following flag is set within cmake
#ifdef PFRING_ZC_ENABLED

#include "PfringObserverCfg.h"
#include "common/msg.h"
#include "core/XMLElement.h"

#include "modules/packet//PfringObserver.h"

#include <string>
#include <vector>
#include <cassert>


PfringObserverCfg* PfringObserverCfg::create(XMLElement* e)
{
	assert(e);
	assert(e->getName() == getName());
	return new PfringObserverCfg(e);
}

PfringObserverCfg::PfringObserverCfg(XMLElement* elem)
	: CfgHelper<PfringObserver, PfringObserverCfg>(elem, "pfringObserver"),
	interface(),
	capture_len(PCAP_DEFAULT_CAPTURE_LENGTH),
	maxPackets(0),
	noInstances(0)
{
	if (!elem) return;  // needed because of table inside ConfigManager

	XMLNode::XMLSet<XMLElement*> set = _elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin();
	     it != set.end();
	     it++) {
		XMLElement* e = *it;

		if (e->matches("interface")) {
			interface = e->getFirstText();
		} else if (e->matches("captureLength")) {
			capture_len = getInt("captureLength");
		} else if (e->matches("maxPackets")) {
			maxPackets = getInt("maxPackets");
		} else if (e->matches("instances")) {
			noInstances = getInt("instances");
		} else if (e->matches("next")) { // ignore next
		} else {
			msg(MSG_FATAL, "Unknown PfringObserver config statement %s\n", e->getName().c_str());
			THROWEXCEPTION("Unknown PfringObserver config statement %s. Please fix config and retry.\n", e->getName().c_str());
			continue;
		}
	}
}

PfringObserverCfg::~PfringObserverCfg()
{

}

PfringObserver* PfringObserverCfg::createInstance()
{
	instance = new PfringObserver(interface, maxPackets, noInstances);

	if (capture_len) {
		if(!instance->setCaptureLen(capture_len)) {
			msg(MSG_FATAL, "PfringObserver: wrong snaplen specified - using %d",
					instance->getCaptureLen());
		}
	}

	if (!instance->prepare()) {
		msg(MSG_FATAL, "PfringObserver: preparing failed");
		THROWEXCEPTION("PfringObserver setup failed!");
	}

	return instance;
}

bool PfringObserverCfg::deriveFrom(PfringObserverCfg* old)
{
	if (interface != old->interface)
		return false;
	if (capture_len != old->capture_len)
		return false;

	return true;
}

#endif /*pfringZC*/
