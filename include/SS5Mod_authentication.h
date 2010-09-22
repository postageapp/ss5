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

#ifndef SS5MOD_AUTHENTICATION_H
#define SS5MOD_AUTHENTICATION_H 1


#define FILE_AUTHENTICATION     0
#define PAM_AUTHENTICATION      2
#define EAP_AUTHENTICATION      3
#define RADIUS_AUTHENTICATION   4


enum ERR_AUTHENTICATION {
     ERR_AUTHECACHE_EXPIRED= -1,
     ERR_NOAUTH=   2
};

/*
 * SS5: Authetication program buffer
 */
struct _S5AuthCmd {
  char ProgName[128];
} *S5AuthCmd;

pthread_mutex_t PAMMutex;

pthread_mutex_t AECMutex;

FILE *S5PwdFile;                 /* Password file pointer  /var/log/ss5.passwd */



/*
 * Initialize module context
 */
UINT
  InitModule( 		struct _module *m
);

/*
 * Master function: does authentication process
 */
UINT
  Authentication(	struct _SS5ClientInfo *ci );

UINT 
  SrvAuthentication(    struct _SS5ClientInfo *ci, 
                        struct _SS5Socks5Data *sd
);

/*
 * Slave functions: manage authentication cache feature
 */
inline UINT
  S5AuthCacheHash(	char *u,
			char *p
);

UINT
  GetAuthCache(		char *u,
			char *p
);

UINT
  UpdateAuthCache(	char *u,
			char *p
);

UINT
  AddAuthCache(		char *u,
			char *p
);

UINT
  FreeAuthCache( 	struct _S5AuthCacheNode **node
);

UINT 
  S5BrowseAuthCacheList( char *buf, 
			 struct _S5AuthCacheNode *node
);


#endif
