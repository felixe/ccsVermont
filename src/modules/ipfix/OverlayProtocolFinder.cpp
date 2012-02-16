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
#include "OverlayProtocols.hpp"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



/**
 * constructs a new instance
 * @param pollinterval sets the interval of polling the hashtable for expired flows
 */
OverlayProtocolFinder::OverlayProtocolFinder(std::string re)
{	
	regex=re;
	msg(MSG_INFO,"OverlayProtocolFinder started");
}


OverlayProtocolFinder::~OverlayProtocolFinder()
{
	
}

//fx, methode mit der ankommende flows verarbeited werden

void OverlayProtocolFinder::onDataRecord(IpfixDataRecord* record)
{
	DPRINTF("Got a Data Record\n");

	bool found=false;

	//egal ob optionsTemplate oder DataTemplate
	//alle felder durchgehn
	for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
		//schaun ob eins frontpayload (oder rev) ist
		if (record->templateInfo->fieldInfo[i].type	== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload,IPFIX_PEN_vermont)
				|| record->templateInfo->fieldInfo[i].type== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont
										| IPFIX_PEN_reverse)) {
			//ist shared pointer hier nötig?? eher nicht, wir removen reference eh am ende
			//boost::shared_ptr<TemplateInfo> templateInfo;
			//templateInfo = record->templateInfo;
			InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
			char* data = (char*)(record->data + record->templateInfo->fieldInfo[i].offset);
			boost::regex bRegex(regex);
			if (boost::regex_search(data, bRegex)) {
					found=true;
			}

		}

	}

	//front und revpayload werden momentan zusammengefasst, müsste man mit if abfrage oben ändern

	if(!found){
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
 * add protocol id to record
 */
void OverlayProtocolFinder::addOverlayProtocol(IpfixDataRecord* record){
	//ist es wirklich nötig hier nochmal den ganzen record durchzuschleifen? oder könnte man das oben gleich einfügen
	//-->muss man weil wir oben nicht das feld overlayProtocol raussuchen...
	//TODO:sollte man hier Fehler werfen falls feld oP nicht gefunden wird, so tipo "sollte vorher gesetzt werden"?
	for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
		InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
		IpfixRecord::Data* data = (record->data + record->templateInfo->fieldInfo[i].offset);
		if (type==InformationElement::IeInfo(IPFIX_ETYPEID_overlayProtocol,IPFIX_PEN_vermont)){
			int id=overlayProtocol_id_lookup(regex);
			if(id==-1){
				THROWEXCEPTION("Problem resolving RegEx: %s to an id",regex.c_str());
			}
			*data=id;
		}
	}

}




