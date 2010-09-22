/* Socks Server 5
 * Copyright (C) 2003 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef SS5DEFS_H
#define SS5DEFS_H 1

enum S4RT {
        S4REQUEST_GRANTED=90,
        S4REQUEST_REJECTED,
        S4REQUEST_IDENTD,
        S4REQUEST_USER_IDSIDENTD};

char *MSGS4RT[]={
        "GRANTED",
        "REJECTED",
        "IDENTD",
        "USER IDSIDENTD"};

enum S5RT {
        S5REQUEST_SUCCEDED,
        S5REQUEST_ISERROR,
        S5REQUEST_ACLDENY,
        S5REQUEST_NETUNREACH,
        S5REQUEST_HOSTUNREACH,
        S5REQUEST_CONNREFUSED,
        S5REQUEST_TTLEXPIRED,
        S5REQUEST_CMDNOTSUPPORT,
        S5REQUEST_ADDNOTSUPPORT,
        S5REQUEST_STARTED,
        S5REQUEST_TERMINATED};

char *MSGS5RT[]={
        "SUCCEDED",
        "ISERROR",
        "ACLDENY",
        "NETUNREACH",
        "HOSTUNREACH",
        "CONNREFUSED",
        "TTLEXPIRED",
        "CMDNOTSUPPORT",
        "ADDNOTSUPPORT",
        "STARTED",
        "TERMINATED"};

enum S5OP {
        CONNECT_NORMAL,
        BIND_NORMAL,
        UDP_ASSOCIATE_NORMAL,
        CONNECT_FAILED,
        BIND_FAILED,
        UDP_ASSOCIATE_FAILED,
        UNKNOWN};

char *MSGS5OP[]={
        "CONNECT",
        "BIND",
        "UDP ASSOCIATE",
        "CONNECT FAILED",
        "BIND FAILED",
        "UDP ASSOCIATE FAILED",
        "UNKNOWN"};

#endif
