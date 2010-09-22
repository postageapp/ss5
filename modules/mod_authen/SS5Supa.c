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


#include "SS5Main.h"
#include "SS5Mod_authentication.h"
#include "SS5Supa.h"

static int
  ss5_secure_dh_decrypt_key(                        int s,
                                                    unsigned char * session_key,
                                                    struct _SS5ClientInfo * ci
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
);




static int ss5_validate_hk_req (struct ss5_hk_req * buf){

  char logString[128];
       
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();


  if (!buf)
    return -1;

  if (buf->stat != 1){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_validate_hk_req - STAT field is not valid %d",pid,buf->stat);
      LOGUPDATE()
    }

    return -1;
  }
  /* XXX check Certificate not implemented yet */
  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] ss5_validate_hk_req - Host Key request validate OK!!",pid);
    LOGUPDATE()
  }

  return 0;
}


static int ss5_secure_send_hk_req (int s, const char * host_key){

  struct ss5_hk_req pippo;
  char logString[128];
       
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();
        
  bzero (&pippo, LEN_HK_REQ);
  pippo.stat = 0x0;
  bcopy (host_key, pippo.key, LEN_KEY);
  if(send(s, &pippo, LEN_HK_REQ, SS5_SEND_OPT) == -1) {
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_send_hk_req - When send Host Key",pid);
      LOGUPDATE()
    }
    return -1;
  }
  return 0;
}

static int ss5_validate_dh_req (int s , struct ss5_dh_req * pippo){

  bzero (pippo, LEN_DH_REQ);
  unsigned char buffer [LEN_DH_REQ];
  uint32_t uint32 = sizeof(uint32_t);
  uint8_t len = 0;
  char logString[128];
       
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /* Receiving DH Data */
  bzero (buffer, LEN_DH_REQ);
  if (recv (s, buffer, LEN_DH_REQ, 0) <= 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_validate_dh_req  - When receive DH Data",pid);
      LOGUPDATE()
    }
    return -1;
  }
  pippo->stat=buffer[0];
  len++;
  bcopy(&(buffer[len]), &(pippo->lenp), uint32);
  len += uint32;
  bcopy (&(buffer[len]), &(pippo->p), pippo->lenp);
  len += pippo->lenp;
  bcopy(&(buffer[len]), &(pippo->leng), uint32);
  len += uint32;
  bcopy (&(buffer[len]), &(pippo->g), pippo->leng);
  len += pippo->leng;
  bcopy(&(buffer[len]), &(pippo->lena), uint32);
  len += uint32;
  bcopy (&(buffer[len]), &(pippo->a), pippo->lena);

  /* Validate Data received */
  if ((pippo->stat != 1)){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_validate_dh_req  - Len data received mismatch or bad request",pid);
      LOGUPDATE()
    }
    return -1;
  }
  return 0;
}


static int ss5_create_dh_response (int s, unsigned char * public_key, uint32_t size){

  struct ss5_dh_res pippo;

  bzero (&pippo, LEN_DH_RES);
  pippo.stat = 0x0;
  pippo.lenb = size;
  bcopy (public_key, pippo.b, size);
  if( send(s, &pippo, (5 + size + 3), SS5_SEND_OPT) == -1)
    return -1;
  return 0;
}


static unsigned char * ss5_secure_dh_compute_key (int s, struct ss5_dh_req * pippo){
        
  DH * ss = DH_new();
  BIGNUM * a = NULL;
  int len = 1;
  unsigned char * public_key = NULL;
  uint32_t len_key = 0;
  uint8_t uint32 = sizeof(uint32_t);
  unsigned char * session_key = NULL;
  char logString[128];
       
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  ss->p = BN_bin2bn ((pippo->p), pippo->lenp,  NULL);
  ss->g = BN_bin2bn ((pippo->g), pippo->leng,  NULL);
  a = BN_bin2bn ((pippo->a), pippo->lena,  NULL);
  if (!a || !ss->p || !ss->g){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_compute_key  - Error when compute a, p, g",pid);
      LOGUPDATE()
    }
    return NULL;
  }       
  do {
    if (ss->pub_key){
      BN_free(ss->pub_key);
      BN_free(ss->priv_key);
    }
    if ( DH_generate_key(ss) == 0){
      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_compute_key - Error when compute the keys",pid);
        LOGUPDATE()
      }
      return NULL; 
    }
  }while(ss->pub_key->neg);

  len_key = BN_num_bytes(ss->pub_key);
  public_key = malloc(len_key);
  if (!public_key){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_compute_key - malloc error",pid);
      LOGUPDATE()
    }
    return NULL;
  }

  BN_bn2bin (ss->pub_key, public_key);
  ss5_create_dh_response(s, public_key, len_key);
#if 0
  printf("B computed: len is %d\n",len_key);
  for (len = 0; len < len_key; len++)
          printf("%02x ", public_key[len]);
  printf("\n");
#endif
  free(public_key);

  /* compute secret key */
  session_key = malloc (DH_size (ss));
  if (!session_key){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_compute_key - malloc error",pid);
      LOGUPDATE()
    }
    return NULL;
  }
  bzero(session_key, DH_size (ss));
  DH_compute_key(session_key, a,  ss);
#if 1
  printf("Key computed:\n");
  for (len = 0; len < DH_size (ss); len++)
    printf("%02x ", session_key[len]);
  printf("\n");
#endif
  return session_key;
}

static int ss5_secure_dh_decrypt_key (int s, unsigned char * session_key, struct _SS5ClientInfo *ci){

  DES_cblock iv, iv2;
  DES_key_schedule schedule1, schedule2;
  unsigned char * pippo_crypt = NULL;
  unsigned char * pippo_crypt2 = NULL;
  uint8_t l = ci->Request[1];
  unsigned char * pippo = &(ci->Request[2]); 
  uint8_t lp = ci->Request[2 + l];
  unsigned char * pippo2 = &(ci->Request[3 + l]); 
  char sk1[8];
  char sk2[8];
  char logString[128];
       
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  pippo_crypt = malloc (METHOD_SIZE);
  if (!pippo_crypt){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_decrypt_key - In malloc!!",pid);
      LOGUPDATE()
    }
    return -1;
  }
  pippo_crypt2 = malloc (METHOD_SIZE);
  if (!pippo_crypt2){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_decrypt_key - In malloc!!",pid);
      LOGUPDATE()
    }
    return -1;
  }
  bzero(pippo_crypt, METHOD_SIZE);
  bzero(pippo_crypt2, METHOD_SIZE);
  bzero (iv, sizeof (DES_cblock));

  /* split the session key in 2 8bit keys */
  bzero(&sk1, 8);
  bzero(&sk2, 8);
  bcopy (session_key, &sk1, 8);
  bcopy (&session_key[8], &sk2, 8);
  
  DES_set_odd_parity ((DES_cblock *) &sk1);
  DES_set_odd_parity ((DES_cblock *) &sk2);
  if ( DES_set_key_checked ((DES_cblock *) &sk1, &schedule1) != 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_decrypt_key - compute first key!",pid);
      LOGUPDATE()
    }
    return -1;
  }

  if ( DES_set_key_checked ((DES_cblock *) &sk2, &schedule2) != 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_dh_decrypt_key - compute second key!",pid);
      LOGUPDATE()
    }
    return -1;
  }

  memset(iv2,'\0',sizeof iv2);
  
  DES_ede3_cbcm_encrypt (pippo, pippo_crypt, l, &schedule1, &schedule2, &schedule1, &iv, &iv2, DES_DECRYPT);      
  bzero (iv, sizeof (DES_cblock));
  memset(iv2,'\0',sizeof iv2);
  DES_ede3_cbcm_encrypt (pippo2, pippo_crypt2, lp, &schedule1, &schedule2, &schedule1, &iv, &iv2, DES_DECRYPT);   

  if( DEBUG() ) {
#if 0
    snprintf(logString,256 - 1,"[%u] [DEBUG] END socks5_3des-cbc_crypt Username: %s ----  Password: %s ---- exiting"
                               " ok from function ",pid,pippo_crypt, pippo_crypt2);
#endif
    snprintf(logString,256 - 1,"[%u] [DEBUG] END socks5_3des-cbc_crypt Username: %s ----  Password: XXXX ---- exiting"
                               " ok from function ",pid,pippo_crypt);
    LOGUPDATE()
  }

  bzero (&(ci->Request[2]), l);
  bzero (&(ci->Request[3 + l]), lp);
  bcopy (pippo_crypt, &(ci->Request[2]), strlen (pippo_crypt));
  bcopy (pippo_crypt2, &(ci->Request[3 + l]), strlen (pippo_crypt2));
  bzero(pippo_crypt, strlen(pippo_crypt));
  bzero(pippo_crypt2, strlen(pippo_crypt2));
  free(pippo_crypt);
  free(pippo_crypt2);
  return 0;
}

int ss5_secure_auth (int sock, struct _SS5ClientInfo *ci){

  char logString[128];
       
  pid_t pid;

  char host_key [] = "SS5_SERVER_S_KEY";  /* must be 16 len */
  struct ss5_dh_req dh_rec;
  unsigned char * session_key = NULL;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /* 
   * XXX for now send a generic string. This must be changed for example generate a DSA/RSA Key from
   * ssh_key_gen and put it into a file named ~/.ss5.conf
   *
   * If set, use user-defined SUPA KEY
   */
  if( SS5SocksOpt.SupaKey[0] != '\0' )
    strncpy(host_key,SS5SocksOpt.SupaKey,16);

  /* Check HOST KEY Request */
  if ( ss5_validate_hk_req ((struct ss5_hk_req *) ci->Request) != 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_auth - Error when Validate request",pid);
      LOGUPDATE()
    }
    return -1;
  }

  /* Send HOST KEY */
  if ( ss5_secure_send_hk_req (sock, host_key) != 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_auth - Error when send Host Key Request request",pid);
      LOGUPDATE()
    }
    return -1;
  }
  
  /* Receive and Validate DH Data */
  if ( ss5_validate_dh_req (sock, &dh_rec) != 0){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_auth - Error when Receive/Validate request",pid);
      LOGUPDATE()
    }
    return -1;
  }
  /* Compute Session Key */
  if ( !(session_key = ss5_secure_dh_compute_key (sock, &dh_rec))){
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] ss5_secure_auth - Error when Compute the session Key",pid);
      LOGUPDATE()
    }
    return -1;
  }
  /* Recieve User/Pwd crypted */
  if( recv(sock, ci->Request, sizeof(ci->Request),0) <= 0 ) {
          bzero(session_key, sizeof(session_key));
          free(session_key);
          return -1;
  }
  /* Decrypt User/Pwd */
  if ( ss5_secure_dh_decrypt_key (sock, session_key, ci) != 0){
          fprintf(stderr, "ERROR - ss5_secure_auth  - Error when Validate request\n");
          bzero(session_key, sizeof(session_key));
          free(session_key);
          return -1;
  }
  
  /* For security */
  bzero(session_key, sizeof(session_key));
  free(session_key);
  
  return 0;
          
}

