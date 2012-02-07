/*
 * OverlayProtocolFinder Module Library
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

#ifndef OVERLAYPROTOCOLFINDER_H
#define OVERLAYPROTOCOLFINDER_H

#include "modules/ipfix/IpfixRecord.hpp"
#include "modules/ipfix/IpfixRecordDestination.h"
#include "core/Module.h"
#include "core/Source.h"


/**
 * blabla
 *
 */
class OverlayProtocolFinder
		: public IpfixRecordDestination,
		  public Module,
		  public Source<IpfixRecord*>
{
public:
	OverlayProtocolFinder(std::string prot);
	virtual ~OverlayProtocolFinder();

	virtual void onDataRecord(IpfixDataRecord* record);

protected:
	string protocol;
	void addOverlayProtocol(IpfixDataRecord* record);
	uint8_t resolveOverlayProtocol(std::string prot);
};

#endif  /*OVERLAYPROTOCOLFINDER_H*/
