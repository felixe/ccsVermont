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

#ifndef IPFIXIDS_H
#define IPFIXIDS_H


#include "core/Module.h"
#include "modules/ipfix/IpfixRecordDestination.h"

/**
 * IPFIX Intrusion Detection System Module
 * 
 * This module takes as input ipfix flows and signature files and checks the flows against the signatures. If a signature matches an alert is written to the given alertfile.
 */
class IpfixIds : public Module, public IpfixRecordDestination, public Source<NullEmitable*>
{
	public:
		IpfixIds(string alertfile = "");
		~IpfixIds();

		virtual void onDataRecord(IpfixDataRecord* record);
		virtual void onTemplate(IpfixTemplateRecord* record);
		virtual void onTemplateDestruction(IpfixTemplateDestructionRecord* record);

	protected:
		void* lastTemplate;
		FILE* fh;

	private:
		string alertfile;

};

#endif
