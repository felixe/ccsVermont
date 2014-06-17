/*
 * Vermont Aggregator Subsystem
 * Copyright (C) 2014 Vermont Project
 * Author: Wolfgang Estgfaeller <wolfgang@estgfaeller.com>
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

#ifndef FLOWANNOTATION_H_
#define FLOWANNOTATION_H_

namespace FlowAnnotation {
    // TCP related annotations
    static const uint32_t TCP_NO_HANDSHAKE    = 0x0001; /**< The observed TCP connection did not start with a TCP handshake */
    static const uint32_t TCP_SEQ_GAPS        = 0x0002; /**< The TCP connection contains at least one sequence gap and these bytes were skipped by the TCPMonitor */
    static const uint32_t TCP_OUT_OF_BUFFER   = 0x0004; /**< TCP reassembly had to be stopped because the configured limit was reached */
    static const uint32_t TCP_CON_EXPIRED     = 0x0008; /**< TCP connection expired because a timeout value has been reached (no valid termination was observed) */

    // HTTP related annotations
    static const uint32_t HTTP_PARSING_ERROR  = 0x0100; /**< a HTTP message was not parsed successful, i.e. a parsing error occurred at some point */
    static const uint32_t HTTP_OUT_OF_BUFFER  = 0x0200; /**< a HTTP message was not parsed successful, i.e. a parsing error occurred at some point */
}

#endif /* FLOWANNOTATION_H_ */
