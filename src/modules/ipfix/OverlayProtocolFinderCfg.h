/*
 * OverlayProtocolFinder Subsystem
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
#ifndef OVERLAYPROTOCOLFINDERCFG_GUARD
#define OVERLAYPROTOCOLFINDERCFG_GUARD

#include "core/Cfg.h"
#include "modules/ipfix/OverlayProtocolFinder.hpp"
#include "modules/ipfix/OverlayProtocols.hpp"


class OverlayProtocolFinderCfg
	: public CfgHelper<OverlayProtocolFinder, OverlayProtocolFinderCfg>
{
public:
	friend class ConfigManager;
	
	virtual ~OverlayProtocolFinderCfg();

	virtual OverlayProtocolFinderCfg* create(XMLElement* elem);
	
	virtual OverlayProtocolFinder* createInstance();
	
	virtual bool deriveFrom(OverlayProtocolFinderCfg* old);


protected:
	std::string protocol;
	OverlayProtocolFinderCfg(XMLElement* elem);
	std::string getFPregex(std::string);
	std::string getrFPregex(std::string);
	std::string getConnective(std::string prot);
	
};
#endif //OVERLAYPROTOCOLFINDERCFG_GUARD
