/*
 * IPFIX Intrusion Detection System Module 
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

#include "IpfixIds.hpp"
#include "common/Time.h"
#include "common/Misc.h"
#include "Connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/**
 * Creates a new IpfixIds.
 * Do not forget to call @c startIpfixIds() to begin printing
 * @return handle to use when calling @c destroyIpfixIds()
 */
IpfixIds::IpfixIds(string alertfile)
	:  alertfile(alertfile)
{
	lastTemplate = 0;
	string file = "";
	fh = stdout;

	msg(MSG_INFO, "IpfixIds started with following parameters:");
	if (alertfile!="") file = "'" + alertfile + "'";
	msg(MSG_INFO, "  - Alertfile =%s", file.c_str());


	//open alertfile for writing
	if (alertfile != "") {
		fh = fopen(alertfile.c_str(), "w");
		if (!fh)
			THROWEXCEPTION("IpfixIds: error opening file '%s': %s (%u)", alertfile.c_str(), strerror(errno), errno);
	}
}

/**
 * Frees memory used by an IpfixIds
 */
IpfixIds::~IpfixIds()
{	
	//close alertfile before shutdown
	if (alertfile != "") {
		int ret = fclose(fh);
		if (ret)
			THROWEXCEPTION("IpfixIds: error closing file '%s': %s (%u)", alertfile.c_str(), strerror(errno), errno);
	}
}


/**
 * called on reception of Ipfix record
 */
void IpfixIds::onDataRecord(IpfixDataRecord* record)
{

	msg(MSG_INFO, "onDataRecord triggered");
	record->removeReference();
}

/**
*called on reception of ipfix template
*/
void IpfixIds::onTemplate(IpfixTemplateRecord* record)
{
	//at the moment do nothing
	record->removeReference();
}

/**
*called on reception of template accounced to be destroyed 
*/
void IpfixIds::onTemplateDestruction(IpfixTemplateDestructionRecord* record)
{
	//at the moment do nothing
	record->removeReference();
}
