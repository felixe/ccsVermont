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

OverlayProtocolFinderCfg::OverlayProtocolFinderCfg(XMLElement* elem)
	: CfgHelper<OverlayProtocolFinder, OverlayProtocolFinderCfg>(elem, "overlayProtocolFinder")
{
	//TODO:fx hier xml argumente aus config file auslesen
}

OverlayProtocolFinderCfg::~OverlayProtocolFinderCfg()
{
	//if (instance == NULL)
		//delete rules;
}

OverlayProtocolFinderCfg* OverlayProtocolFinderCfg::create(XMLElement* elem)
{
	assert(elem);
	assert(elem->getName() == getName());
	return new OverlayProtocolFinderCfg(elem);
}

OverlayProtocolFinder* OverlayProtocolFinderCfg::createInstance()
{
	instance = new OverlayProtocolFinder(44);
	return instance;
}

bool OverlayProtocolFinderCfg::deriveFrom(OverlayProtocolFinderCfg* old)
{
	return false;  // FIXME: implement it, to gain performance increase in reconnect
}

