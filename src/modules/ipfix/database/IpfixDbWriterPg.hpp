/*
 * IPFIX Database Reader/Writer
 * Copyright (C) 2006 Jürgen Abberger
 * Copyright (C) 2006 Lothar Braun <braunl@informatik.uni-tuebingen.de>
 * Copyright (C) 2007 Gerhard Muenz
 * Copyright (C) 2008 Tobias Limmer
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

/* Some constants that are common to IpfixDbWriter and IpfixDbReader */
#ifdef PG_SUPPORT_ENABLED

#ifndef IPFIXDBWRITERPG_H
#define IPFIXDBWRITERPG_H

#include "IpfixDbCommon.hpp"
#include "IpfixDbWriterSQL.hpp"
#include "../IpfixRecordDestination.h"
#include "common/ipfixlolib/ipfix.h"
#include "common/ipfixlolib/ipfixlolib.h"
#include <libpq-fe.h>
#include <netinet/in.h>
#include <time.h>

#define EXPORTERID 0

/**
 * IpfixDbWriterPg powered the communication to the database server
 * also between the other structs
 */
class IpfixDbWriterPg
	: public IpfixDbWriterSQL
{
	public:
		IpfixDbWriterPg(const char* dbType, const char* host, const char* db,
				const char* user, const char* pw,
				unsigned int port, uint16_t observationDomainId, // FIXME: observationDomainId
				int maxStatements, vector<string> columns, bool legacyNames);
		~IpfixDbWriterPg();

		virtual void connectToDB();
		virtual bool writeToDb();
		virtual int createExporterTable();
		virtual int getExporterID(IpfixRecord::SourceID* sourceID);
		virtual bool createDBTable(const char* partitionname, uint64_t starttime, uint64_t endtime);

	protected:
		PGconn* conn;
		bool checkRelationExists(const char* relname);

};


#endif


#endif
