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
#ifndef OVERLAYPROTOCOLS_GUARD
#define OVERLAYPROTOCOLS_GUARD

#include <string>

/**
 * describes an OverlayProtocol
 * name -> well, obvious
 * id -> the id that the ipfix key overlayProtocol will have if flow matches given oP
 * FPregex -> regular expression (see http://www.boost.org/doc/libs/1_48_0/libs/regex/doc/html/boost_regex/syntax/perl_syntax.html for syntax)
 * 			that will be searched in payload.
 * rFPreged -> same as FPregex, will be searched for in reverseFrontPayload (in most cases the server response)
 * connective -> logical connection between both regexes, at the moment only "OR" and "AND" are supported
 */
struct overlayProtocol {
	std::string name;
	int id;
	std::string FPregex;
	std::string rFPregex;
	std::string connective;
};

const std::string overlayProtocol_FPregex_lookup(std::string n);
const std::string overlayProtocol_rFPregex_lookup(std::string n);
const std::string overlayProtocol_connective_lookup(std::string n);
const int overlayProtocol_id_lookup(std::string n,std::string m);






#endif //OVERLAYPROTOCOLS
