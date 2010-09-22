/* Socks Server 5
 * Copyright (C) 2010 by Raffaele De Lorenzo - <raffaele.delorenzo@libero.it>

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

#ifndef SS5SUPA_H
#define SS5SUPA_H 1

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/des.h>

#define LEN_KEY 16
#define LEN_HK_REQ 17
struct ss5_hk_req {

        uint8_t stat;
        uint8_t key[LEN_KEY];
};

#define LEN_DH_REQ 778
#define METHOD_SIZE 255
struct ss5_dh_req {

        uint8_t stat;
        uint32_t lenp;
        uint8_t p[METHOD_SIZE];
        uint32_t leng;
        uint8_t g[METHOD_SIZE];
        uint32_t lena;
        uint8_t a[METHOD_SIZE]; 
};

#define LEN_DH_RES 260
struct ss5_dh_res {

        uint8_t stat;
        uint32_t lenb;
        uint8_t b[METHOD_SIZE];
};

#define LEN_AUTH_REQ 513
struct ss5_auth_req{
        uint8_t ver;
        uint8_t ulen;
        uint8_t uname[METHOD_SIZE];
        uint8_t plen;
        uint8_t password[METHOD_SIZE];
};

/*
 * Functions for SUPA
 */
UINT
  S5PwdFileOpen(	pid_t pid
);

int 
  ss5_secure_auth(	                            int sock, 
                                                    struct _SS5ClientInfo *ci
);

/*static int 
  ss5_secure_dh_decrypt_key(                        int s, 
                                                    unsigned char * session_key, 
                                                    struct _SS5BasicData * bd
);

static unsigned char *
  ss5_secure_dh_compute_key(                        int s, 
                                                    struct ss5_dh_req * pippo
);

static int 
  ss5_create_dh_response(                           int s, 
                                                    unsigned char * public_key, 
                                                    uint32_t size
);

static int ss5_validate_dh_req(                     int s, 
                                                    struct ss5_dh_req * pippo
);

static int ss5_secure_send_hk_req(                  int s, 
                                                    const char * host_key
);

static int 
  ss5_validate_hk_req(                              struct ss5_hk_req * buf
);*/

#endif
