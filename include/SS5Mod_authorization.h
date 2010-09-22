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

#ifndef SS5MOD_AUTHORIZATION_H
#define SS5MOD_AUTHORIZATION_H 1

#define LDAP_BASE       0
#define LDAP_FILTER     1

#define PERMIT          0
#define DENY            1

#define PROXY           0
#define NOPROXY         1

#define FILE_PROFILING  0
#define LDAP_PROFILING  1
#define MYSQL_PROFILING  2

UINT      NAclList,
            _tmp_NAclList;

UINT      NLdapStore;
UINT      NMysqlStore;


enum ERR_AUTHORIZATION {
     ERR_NOACLFOUND= -1,
     ERR_DENY=       -2,
     ERR_AUTHOCACHE_EXPIRED=    -3
};

pthread_mutex_t ACMutex;

/*
 * Initialize module context
 */
UINT
  InitModule(		struct _module *m
);

/*
 * Master function: does authorization for connect/bind (Pre) and
 * udp associate (Post) commands
 */
UINT
  PreAuthorization(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Facilities *fa
);

UINT
  PostAuthorization(	struct _SS5ClientInfo *ci,
			struct _SS5RequestInfo *ri,
			struct _SS5Facilities *fa
);

UINT
  SrvAuthorization( struct _SS5ClientInfo *ci, 
                    struct _SS5Socks5Data *sd
);

/*
 * Slave functions: manage access lists
 */
UINT
  AddAcl(		UINT ctx,
                        UINT type,
			ULINT sa,
                        char sfqdn[64],
			ULINT sp,
			ULINT da,
                        char dfqdn[64],
			ULINT dp,
			UINT srcmask,
			UINT dstmask,
			UINT method,
			struct _SS5Facilities *fa
);

UINT 
  DelAcl(               UINT type, 
                        ULINT sa, 
                        char sfqdn[64],
                        ULINT sp, 
                        ULINT da, 
                        char dfqdn[64],
                        ULINT dp, 
                        UINT srcmask, 
                        UINT dstmask, 
                        UINT method, 
                        struct _SS5Facilities *fa);


INT
  GetAcl(		ULINT sa,
			UINT sp,
			ULINT da,
			UINT dp,
			struct _SS5Facilities *fa,
			UINT *acl
);

UINT
  FreeAcl( 		struct _S5AclNode **node
);

UINT
  BrowseAclList(        char *buf,struct _S5AclNode *node
);

UINT
  S5CheckPort(		char *port,
			UINT s5port
);

UINT 
  S5BrowseAclList( 	char *buf, 
			struct _S5AclNode *node
);

UINT 
  S5BrowseAuthoCacheList( char *buf, 
			  struct _S5AuthoCacheNode *node
);

UINT 
  S5CheckexpDate(	char *expdate
);

ULINT
  FqdnHash(		char *s
);

/*
 * Look for username into group file or group into directory
 */
inline UINT
  FileCheck(		char *group,
			char *user
);

/*
 * Slave functions: manage authorization cache feature
 */
inline UINT
  S5AuthoCacheHash(     char *sa,
                        char *da,
                        UINT dp,
                        char *u
);

UINT
  GetAuthoCache(        char *sa,
                        char *da,
                        UINT dp,
                        char *u,
			struct _SS5Facilities *fa,
                        UINT f 
);

UINT
  UpdateAuthoCache(     char *sa,
                        char *da,
                        UINT dp,
                        char *u,
                        UINT f
);

UINT
  AddAuthoCache(        char *sa,
                        char *da,
                        UINT dp,
                        char *u,
			struct _SS5Facilities *fa
);

UINT
  FreeAuthoCache(        struct _S5AuthoCacheNode **node
);

#endif
