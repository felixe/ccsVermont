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

#ifndef PFRINGOBSERVERCFG_H_
#define PFRINGOBSERVERCFG_H_

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <core/XMLElement.h>
#include <core/Cfg.h>

#include <modules/packet//PfringObserver.h>

#include <core/InstanceManager.h>
#include <map>

class PfringObserver;

class PfringObserverCfg
	: public CfgHelper<PfringObserver, PfringObserverCfg>
{
public:
	friend class ConfigManager;

	virtual PfringObserverCfg* create(XMLElement* e);

	virtual ~PfringObserverCfg();

	virtual PfringObserver* createInstance();

	virtual bool deriveFrom(PfringObserverCfg* old);

protected:
	PfringObserverCfg(XMLElement*);

private:
	// config variables
	std::string interface;	// also used for filename in offline mode
	//std::string pcap_filter;
	unsigned int capture_len;
	bool offline;
	bool replaceOfflineTimestamps;
	bool offlineAutoExit;
	float offlineSpeed;
	uint64_t maxPackets;
	int noInstances; // defines the number of instances which should be preallocated by the instance manager
};

#endif /*PFRINGOBSERVERCFG_H_*/
#endif /*pfringZC*/
