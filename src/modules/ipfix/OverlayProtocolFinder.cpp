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



#include "OverlayProtocolFinder.hpp"
#include "common/Time.h"
#include "common/Misc.h"
#include "Connection.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string>





/**
 * constructs a new instance
 * @param pollinterval sets the interval of polling the hashtable for expired flows
 */
OverlayProtocolFinder::OverlayProtocolFinder(std::string prot)
{	
	protocol=prot;
	msg(MSG_INFO,"OverlayProtocolFinder started");
}


OverlayProtocolFinder::~OverlayProtocolFinder()
{
	
}

//fx, methode mit der ankommende flows verarbeited werden

void OverlayProtocolFinder::onDataRecord(IpfixDataRecord* record)
{
	DPRINTF("Got a Data Record\n");

	//sollte man genauer machen und nicht einfach max nehmen...
	//char payload[65535];
	string payload="";

	//egal ob optionsTemplate oder DataTemplate
	//alle felder durchgehn
	for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
		//schaun ob eins frontpayload (oder rev) ist
		if (record->templateInfo->fieldInfo[i].type	== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload,IPFIX_PEN_vermont)
				|| record->templateInfo->fieldInfo[i].type== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont
										| IPFIX_PEN_reverse)) {


			//ist shared pointer hier nötig??
			//boost::shared_ptr<TemplateInfo> templateInfo;
			//templateInfo = record->templateInfo;

			InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
			IpfixRecord::Data* data = (record->data + record->templateInfo->fieldInfo[i].offset);
//			if ((type.enterprise!=0) && (type.enterprise!=IPFIX_PEN_reverse)){
//				//haben wir das nicht schon oben getestet?
//				if (type==InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont) ||
//								type==InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont|IPFIX_PEN_reverse)){

					for (uint32_t i = 0; i <type.length; i++) {
						char c = data[i];	//diese umwandlung passt, printed ja auch schön
						//printf("%c",c);
						//payload[i] = c;   //hier wird richtig eingefügt, verliert aber mit der Zeit den ersten "block",
						if (isprint(c)){
							payload+=c;
						}//geht es ineffizienter? wird jedes mal speicher neu allozieren müssen?!

				//	}
			//	}
			}

		}

	}

	//front und revpayload werden momentan zusammengefasst, müsste man mit if abfrage oben ändern
	//dass geht natüüüürlich auch schneller und schöner, nennen wirs mal "proof of concept":

	//std::string payloadStr(payload); //umwandeln in string funktioniert einwandfrei
	std::string::size_type foundAt = payload.find(protocol);
	//std::string::size_type foundAt2 = payload.find("GET /mapfiles/");
	if((foundAt==std::string::npos)){	//&&(foundAt2==std::string::npos)){
		//printf("\nnot found\n");
		record->removeReference();
	}else{
		//adding to record which protocol detected
		addOverlayProtocol(record);
		send(record);
		record->removeReference();
	}
}
/**
 * add protocol tag to record
 */
void OverlayProtocolFinder::addOverlayProtocol(IpfixDataRecord* record){
	for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
		InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
		IpfixRecord::Data* data = (record->data + record->templateInfo->fieldInfo[i].offset);
		if (type==InformationElement::IeInfo(IPFIX_ETYPEID_overlayProtocol,IPFIX_PEN_vermont)){
			*data=resolveOverlayProtocol(protocol);
		}
	}

}

uint8_t OverlayProtocolFinder::resolveOverlayProtocol(std::string prot){
	if(prot=="GET /maps/"){
		return 1;
	}else{
		THROWEXCEPTION("Could not resolve used protocol string");
	}

}



