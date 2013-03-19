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

#include "LibzeroObserverCfg.h"
#include "common/msg.h"
#include "core/XMLElement.h"

#include "modules/packet//LibzeroObserver.h"

#include <string>
#include <vector>
#include <cassert>


LibzeroObserverCfg* LibzeroObserverCfg::create(XMLElement* e)
{
	assert(e);
	assert(e->getName() == getName());
	return new LibzeroObserverCfg(e);
}

int LibzeroObserverCfg::numLibzeroObservers;

LibzeroObserverCfg::LibzeroObserverCfg(XMLElement* elem)
	: CfgHelper<LibzeroObserver, LibzeroObserverCfg>(elem, "libzeroObserver"),
	interface(),
	pcap_filter(),
	capture_len(PCAP_DEFAULT_CAPTURE_LENGTH),
	offline(false),
	maxPackets(0)
{
	if (!elem) return;  // needed because of table inside ConfigManager

	XMLNode::XMLSet<XMLElement*> set = _elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin();
	     it != set.end();
	     it++) {
		XMLElement* e = *it;

		if (e->matches("interface")) {
			interface = e->getFirstText();
		} else if (e->matches("pcap_filter")) {
			pcap_filter = e->getFirstText();
		} else if (e->matches("replaceTimestamps")) {
			replaceOfflineTimestamps = getBool("replaceTimestamps", replaceOfflineTimestamps);
		} else if (e->matches("captureLength")) {
			capture_len = getInt("captureLength");
		} else if (e->matches("maxPackets")) {
			maxPackets = getInt("maxPackets");
		} else if (e->matches("next")) { // ignore next
		} else {
			msg(MSG_FATAL, "Unknown observer config statement %s\n", e->getName().c_str());
			continue;
		}
	}
    LibzeroObserverCfg::numLibzeroObservers++;
}

LibzeroObserverCfg::~LibzeroObserverCfg()
{
    LibzeroObserverCfg::numLibzeroObservers--;
}

LibzeroObserver* LibzeroObserverCfg::createInstance()
{
	instance = new LibzeroObserver(interface, numLibzeroObservers, maxPackets);

	if (capture_len) {
		if(!instance->setCaptureLen(capture_len)) {
			msg(MSG_FATAL, "LibzeroObserver: wrong snaplen specified - using %d",
					instance->getCaptureLen());
		}
	}

	if (!instance->prepare(pcap_filter.c_str())) {
		msg(MSG_FATAL, "LibzeroObserver: preparing failed");
		THROWEXCEPTION("LibzeroObserver setup failed!");
	}

	return instance;
}

bool LibzeroObserverCfg::deriveFrom(LibzeroObserverCfg* old)
{
	if (interface != old->interface)
		return false;
	if (capture_len != old->capture_len)
		return false;
	if (pcap_filter != old->pcap_filter)
		return false;

	return true;
}
