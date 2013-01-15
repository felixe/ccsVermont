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

#include "ObserverCfg.h"
#include "common/msg.h"
#include "core/XMLElement.h"

#include "modules/packet//Observer.h"

#include <string>
#include <vector>
#include <cassert>
#include <iostream>

#include <string>
#include <boost/foreach.hpp>
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;



ObserverCfg* ObserverCfg::create(XMLElement* e)
{
	assert(e);
	assert(e->getName() == getName());
	return new ObserverCfg(e);
}

ObserverCfg::ObserverCfg(XMLElement* elem)
	: CfgHelper<Observer, ObserverCfg>(elem, "observer"),
	interface(),
	pcap_filter(),
	capture_len(PCAP_DEFAULT_CAPTURE_LENGTH),
	offline(false),
	replaceOfflineTimestamps(false),
	offlineAutoExit(true),
	offlineSpeed(1.0),
	maxPackets(0),
	sampling(1)
{
	if (!elem) return;  // needed because of table inside ConfigManager

	XMLNode::XMLSet<XMLElement*> set = _elem->getElementChildren();
	for (XMLNode::XMLSet<XMLElement*>::iterator it = set.begin(); it != set.end(); it++) {
		XMLElement* e = *it;

		if (e->matches("interface")) {
			interface = e->getFirstText();
		} else if (e->matches("pcap_filter")) {
			pcap_filter = e->getFirstText();
		} else if (e->matches("filename")) {
			interface = e->getFirstText();
			offline = true;
		} else if (e->matches("replaceTimestamps")) {
			replaceOfflineTimestamps = getBool("replaceTimestamps", replaceOfflineTimestamps);
		} else if (e->matches("offlineSpeed")) {
			offlineSpeed = getDouble("offlineSpeed");
		} else if (e->matches("offlineAutoExit")) {
			offlineAutoExit = getBool("offlineAutoExit", offlineAutoExit);
		} else if (e->matches("captureLength")) {
			capture_len = getInt("captureLength");
		} else if (e->matches("maxPackets")) {
			maxPackets = getInt("maxPackets");
		} else if (e->matches("pfring_sampling")) {
			sampling = getInt("pfring_sampling");
		} else if (e->matches("wildcard")) {


			filtering_rule tmp;
			memset(&tmp, 0, sizeof(tmp));

			tmp.rule_id = filter.size() + 1;
			tmp.rule_action = dont_forward_packet_and_stop_rule_evaluation;
							

			XMLNode::XMLSet<XMLElement*> wild = e->getElementChildren();			
			for (XMLNode::XMLSet<XMLElement*>::const_iterator _it = wild.begin();  _it != wild.end(); _it++) {
				XMLElement *_e = *_it;

				if (_e->matches("action")) {
					int a = 0;
					a = getInt("action");
					if (a==1)
						tmp.rule_action = forward_packet_and_stop_rule_evaluation;
					else
						tmp.rule_action = dont_forward_packet_and_stop_rule_evaluation;
				} else if (_e->matches("smac")) {

					u_int8_t s[ETH_ALEN];

					string mac = _e->getFirstText();
					char_separator<char> sep(":");
					tokenizer< char_separator<char> > tokens(mac, sep);
					int i = 0;
					BOOST_FOREACH(const string &t, tokens) {
						stringstream ss(t);
						int n;
						ss >> std::hex >> n;
						s[i] = n;
						i++;
					}
					 memcpy(&tmp.core_fields.smac, &s, sizeof(s));
				} else if (_e->matches("dmac")) {
					u_int8_t d[ETH_ALEN];

					std::string mac = _e->getFirstText();
					char_separator<char> sep(":");
					tokenizer< char_separator<char> > tokens(mac, sep);
					int i = 0;
					BOOST_FOREACH(const string &t, tokens) {

						stringstream ss(t);
						int n;
						ss >> std::hex >> n;
						d[i] = n;
						i++;
					}

					memcpy(&tmp.core_fields.dmac, &d, sizeof(d));
				} else if (_e->matches("vlan")) {
					tmp.core_fields.vlan_id = getInt("vlan");
				} else if (_e->matches("proto")) {
					int b = atoi((_e->getFirstText()).c_str());
					tmp.core_fields.proto = b;
				} else if (_e->matches("shost")) {
					string sh = _e->getFirstText();
					const char *addr = sh.c_str();
					tmp.core_fields.shost.v4 = ntohl(inet_addr(addr));
					tmp.core_fields.shost_mask.v4 = 0xFFFFFFFF;
				} else if (_e->matches("dhost")) {
					string dh = _e->getFirstText();
					const char *addr = dh.c_str();
					tmp.core_fields.dhost.v4 = ntohl(inet_addr(addr));
					tmp.core_fields.shost_mask.v4 = 0xFFFFFFFF;
				} else if (_e->matches("shost_mask")) {
					u_int32_t s_mask;
					string shm = _e->getFirstText();
					tmp.core_fields.shost_mask.v4 = ntohl(inet_addr(shm.c_str()));
				} else if (_e->matches("dhost_mask")) {
					string dhm = _e->getFirstText();
					const char *addr = dhm.c_str();
					tmp.core_fields.dhost_mask.v4 = ntohl(inet_addr(dhm.c_str()));
				} else if (_e->matches("sport_low")) {
					tmp.core_fields.sport_low = atoi((_e->getFirstText()).c_str());
				} else if (_e->matches("sport_high")) {
					tmp.core_fields.sport_high = atoi((_e->getFirstText()).c_str());
				} else if (_e->matches("dport_low")) {
					tmp.core_fields.dport_low = atoi((_e->getFirstText()).c_str());
				} else if (_e->matches("dport_high")) {
					tmp.core_fields.dport_high = atoi((_e->getFirstText()).c_str());
				} else {
					msg(MSG_FATAL, "Unknown wildcard filter config statement %s\n", _e->getName().c_str());
				}
			}
			filter.push_back(tmp);
 		} else if (e->matches("bpf")) {
			bpf_filter = e->getFirstText();
		} else if (e->matches("hwf")) {
			string hf = "ethtool -U " + interface + " ";

			XMLNode::XMLSet<XMLElement*> hwf = e->getElementChildren();
			for (XMLNode::XMLSet<XMLElement*>::const_iterator _it = hwf.begin();  _it != hwf.end(); _it++) {
				XMLElement *_e = *_it;

				if (_e->matches("flowType")) {
					hf += "flow-type " + _e->getFirstText() + " ";
				} else if (_e->matches("src")) {
					hf += "src " + _e->getFirstText() + " ";
				} else if (_e->matches("dst")) {
					hf += "dst " + _e->getFirstText() + " ";
				} else if (_e->matches("prot")) {
					hf += "proto " + _e->getFirstText() + " ";
				} else if (_e->matches("srcIP")) {
					hf += "src-ip " + _e->getFirstText() + " ";
				} else if (_e->matches("dstIP")) {
					hf += "dst-ip " + _e->getFirstText() + " ";
				} else if (_e->matches("tos")) {
					hf += "tos " + _e->getFirstText() + " ";
				} else if (_e->matches("l4proto")) {
					hf += "l4proto " + _e->getFirstText() + " ";
				} else if (_e->matches("srcPort")) {
					hf += "src-port " + _e->getFirstText() + " ";
				} else if (_e->matches("dstPort")) {
					hf += "dst-port " + _e->getFirstText() + " ";
				} else if (_e->matches("spi")) {
					hf += "spi " + _e->getFirstText() + " ";
				} else if (_e->matches("vlanType")) {
					hf += "vlan-etype " + _e->getFirstText() + " ";
				} else if (_e->matches("vlan")) {
					hf += "vlan " + _e->getFirstText() + " ";
				} else if (_e->matches("userDef")) {
					hf += "user-def " + _e->getFirstText() + " ";
				} else if (_e->matches("action")) {
					hf += "action " + _e->getFirstText() + " ";
				} else if (_e->matches("loc")) {
					hf += "loc " + _e->getFirstText() + " ";
				} else {
					msg(MSG_FATAL, "Unknown hwf filter config statement %s\n", _e->getName().c_str());
				}
			}
			hw_filter.push_back(hf);
		} else if (e->matches("next")) { // ignore next
		} else {
			msg(MSG_FATAL, "Unknown observer config statement %s\n", e->getName().c_str());
			continue;
		}
	}
}


ObserverCfg::~ObserverCfg()
{

}

Observer* ObserverCfg::createInstance()
{
	instance = new Observer(interface, offline, maxPackets);
	instance->setOfflineSpeed(offlineSpeed);
	instance->setOfflineAutoExit(offlineAutoExit);
	if (replaceOfflineTimestamps) instance->replaceOfflineTimestamps();

	if (capture_len) {
		if(!instance->setCaptureLen(capture_len)) {
			msg(MSG_FATAL, "Observer: wrong snaplen specified - using %d",
					instance->getCaptureLen());
		}
	}

	if (!instance->prepare(pcap_filter.c_str(), sampling, filter, bpf_filter, hw_filter)) {
		msg(MSG_FATAL, "Observer: preparing failed");
		THROWEXCEPTION("Observer setup failed!");
	}

	return instance;
}

bool ObserverCfg::deriveFrom(ObserverCfg* old)
{
	if (interface != old->interface)
		return false;
	if (capture_len != old->capture_len)
		return false;
	if (pcap_filter != old->pcap_filter)
		return false;

	return true;
}
