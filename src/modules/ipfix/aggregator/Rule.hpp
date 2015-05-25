/*
 * IPFIX Concentrator Module Library
 * Copyright (C) 2004 Christoph Sommer <http://www.deltadevelopment.de/users/christoph/ipfix/>
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

#ifndef RULE_H
#define RULE_H

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "modules/ipfix/IpfixReceiver.hpp"
#include "modules/ipfix/IpfixPrinter.hpp"

#define MAX_RULE_FIELDS 255

class BaseHashtable;

/**
 * Single aggregation rule
 */
class Rule : private PrintHelpers {
	public:

		/**
		 * Single field of an aggregation rule.
		 */
		class Field {
			public:
				Field() {
					type.id = 0;
					type.length = 0;
					type.enterprise = 0;
					pattern = NULL;
					modifier = Rule::Field::DISCARD;
				}

				~Field() {
					free(pattern);
				}

				/*
				 * Rule::Field Modifier can be DISCARD (throw away this field), KEEP (keep this field), AGGREGATE (create one aggregate flow per different field value) or between MASK_START and MASK_END (to determine how many bits of the IP Address to keep)
				 */
				enum Modifier {DISCARD = 0, KEEP = 1, AGGREGATE = 2, MASK_START = 126, MASK_END = 254};

				InformationElement::IeInfo type; /**< field type this Rule::Field refers to */
				IpfixRecord::Data* pattern; /**< pattern to match fields against to determine applicability of a rule. A pattern of NULL means no pattern needs to be matched for this field */
				Rule::Field::Modifier modifier; /**< modifier to apply to the corresponding field if this rule is matched */
		};


		Rule();
		~Rule();
		void initialize();
		void print();
		bool ExptemplateDataMatches(const Packet* p);
		int dataRecordMatches(IpfixDataRecord* record);

		uint16_t id;
		uint16_t preceding;
		int fieldCount;
		uint32_t biflowAggregation;	/**< true if biflows have to be aggregated */
		uint32_t httpAggregation;	/**< true if http-flows have to be aggregated */
		uint32_t httpSkipHeader;    /**< true if the HTTP msg header payload aggregation should be skipped, instead only the msg body will be exported */
		uint32_t httpMsgBufferSize; /**< The maximal number of bytes buffered per HTTP message if payload needs to be combined to be parsed successfully. */
		uint32_t tcpmonTimeoutAttempt;   /**< expiry timeout for TCP connection attempts in the TcpMonitor */
		uint32_t tcpmonTimeoutEstablished; /**< expiry timeout for inactive established TCP connections in the TcpMonitor */
		uint32_t tcpmonTimeoutClosed;      /**< expiry timeout for closed TCP connections in the TcpMonitor */
		uint32_t tcpmonBufferSize; /**< The maximal number of bytes buffered per TCP connection if segments are out-of-order. */
		bool tcpmonPCAPTimestamps; /**< Whether or not PCAP timestamps should be used as time reference for stream expiry */

		Rule::Field* field[MAX_RULE_FIELDS];
		BaseHashtable* hashtable;

	private:
		Packet::IPProtocolType validProtocols; /**< types of protocols which are valid for specified rule */
		Rule::Field** patternFields;  /**< contains array of rules which contain a pattern for packet matching */
		uint16_t patternFieldsLen;
};

#endif
