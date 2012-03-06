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
OverlayProtocolFinder::OverlayProtocolFinder(std::string FPrx, std::string rFPrx, std::string conn)
{	
	FPregex=FPrx;
	rFPregex=rFPrx;
	connective=conn;

	if(FPregex==""&&rFPregex==""){
		THROWEXCEPTION("Protocol with two emtpy regular expressions does not make sense. Please change OverlayProtocol");
	}

	msg(MSG_INFO,"OverlayProtocolFinder started");
}


OverlayProtocolFinder::~OverlayProtocolFinder()
{
	
}

void OverlayProtocolFinder::onDataRecord(IpfixDataRecord* record)
{
	DPRINTF("Got a Data Record\n");

	bool found;
	bool revFound;
	//if both regex are emtpy program throws exception (in opfcfg)
	//connective has to be OR or AND if not exception has already been thrown
	if(FPregex==""&&connective=="AND"){
		found=true;
	}else{
		found=false;
	}
	if(rFPregex==""&&connective=="AND"){
		revFound=true;
	}else{
		revFound=false;
	}

	//egal ob optionsTemplate oder DataTemplate
	//alle felder durchgehn
	for (uint32_t i = 0; i < record->templateInfo->fieldCount; i++) {
		//schaun ob eins frontpayload (oder rev) ist
		if (FPregex!=""&&(record->templateInfo->fieldInfo[i].type	== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload,IPFIX_PEN_vermont))) {
			//ist shared pointer hier nötig?? eher nicht, wir removen reference eh am ende
			//boost::shared_ptr<TemplateInfo> templateInfo;
			//templateInfo = record->templateInfo;
			InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
			char* data = (char*)(record->data + record->templateInfo->fieldInfo[i].offset);
			boost::regex boostFPregex(FPregex);
			if (boost::regex_search(data, boostFPregex)) {
					found=true;
			}
		}
		//zur Erinnerung: reverse types werden mit bitweiser or verknüpfung mit PEN realisiert
		if (rFPregex!=""&&(record->templateInfo->fieldInfo[i].type== InformationElement::IeInfo(IPFIX_ETYPEID_frontPayload, IPFIX_PEN_vermont
										| IPFIX_PEN_reverse))) {;
			InformationElement::IeInfo type =	record->templateInfo->fieldInfo[i].type;
			char* data = (char*)(record->data + record->templateInfo->fieldInfo[i].offset);
			boost::regex boostrFPregex(rFPregex);
			if (boost::regex_search(data, boostrFPregex)) {
					revFound=true;
			}
		}
	}

	if(connective=="AND"){
		if(found&&revFound){
			//adding to record which protocol detected
			addOverlayProtocol(record);
			send(record);
			record->removeReference();
		}else{
				//drop record
				record->removeReference();

		}
	}
	if(connective=="OR"){
		if(found||revFound){
			//adding to record which protocol detected
			addOverlayProtocol(record);
			send(record);
			record->removeReference();
		}else{
			//drop record
			record->removeReference();
		}

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
			int id=overlayProtocol_id_lookup(FPregex,rFPregex);
			if(id==-1){
				THROWEXCEPTION("Problem resolving RegExes: %s or %s to an id",FPregex.c_str(),rFPregex.c_str());
			}
			*data=id;
		}
	}

}




