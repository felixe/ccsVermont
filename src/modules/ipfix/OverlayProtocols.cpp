/*
 * OverlayProtocols
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
#ifndef OVERLAYPROTOCOLSC_GUARD
#define OVERLAYPROTOCOLSC_GUARD

#include "modules/ipfix/OverlayProtocols.hpp"

/*
 * add new protocols to this struct
 * NOTE: "NOTFOUND" as regex is reserved, see below
 *
 */
struct overlayProtocol oProtocols[]={
//for a definition of how to form regexes here see boost.regex manual
		{"googleMaps",1,"GET /maps/|GET /vt/|GET /mapfiles/|GET /kh|GET /cat_js/|GET /intl/.*\.js |GET /intl/.*\.png |GET /intl/.*\.gif ",
						"GET /maps/|GET /vt/|GET /mapfiles/|GET /kh|GET /cat_js/|GET /intl/.*\.js |GET /intl/.*\.png |GET /intl/.*\.gif ","OR"},

};

/**
 * returns id if regex re exists, -1 if not
 */
const int overlayProtocol_id_lookup(std::string FPrx,std::string rFPrx)
{
	int i;
	for (i=0; i<sizeof(oProtocols)/sizeof(struct overlayProtocol); i++) {
		if (oProtocols[i].FPregex==FPrx&&oProtocols[i].rFPregex==rFPrx) {
			return oProtocols[i].id;
		}
	}
	return -1;
}

/**
 * returns regex as string if protocol n exists, "NOTFOUND" if not
 */
const std::string overlayProtocol_FPregex_lookup(std::string n)
{
	int i;
	for (i=0; i<sizeof(oProtocols)/sizeof(struct overlayProtocol); i++) {
		if (oProtocols[i].name==n) {
			return oProtocols[i].FPregex;
		}
	}
	return "NOTFOUND";
}

/**
 * returns regex as string if protocol n exists,"NOTFOUND" if not
 */
const std::string overlayProtocol_rFPregex_lookup(std::string n)
{
	int i;
	for (i=0; i<sizeof(oProtocols)/sizeof(struct overlayProtocol); i++) {
		if (oProtocols[i].name==n) {
			return oProtocols[i].rFPregex;
		}
	}
	return "NOTFOUND";
}

/**
 * returns connective as string if protocol n exists,"NOTFOUND" if not
 */
const std::string overlayProtocol_connective_lookup(std::string n){
	int i;
	for (i=0; i<sizeof(oProtocols)/sizeof(struct overlayProtocol); i++) {
		if (oProtocols[i].name==n) {
			return oProtocols[i].connective;
		}
	}
	return "NOTFOUND";
}
#endif
