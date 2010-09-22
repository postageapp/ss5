/* Socks Server 5
 * Copyright (C) 2002 - 2010 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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

/*
 * $Id: SS5Mod_authentication.c, Ver 3.7 08-2005 20:00:00 Matteo Ricchetti Exp $
 */

#include"SS5Main.h"
#include"SS5Mod_authentication.h"
#include"SS5Mod_log.h"
#include"SS5Basic.h"
#include"SS5Radius.h"
#include"SS5ExternalProgram.h"
#include"SS5Pam.h"
#include"SS5Supa.h"

#ifdef SS5_USE_GSSAPI
#include"SS5GSSApi.h"
#endif

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->Authentication = Authentication;
  m->FreeAuthCache  = FreeAuthCache;
  m->SrvAuthentication = SrvAuthentication;
 
  return OK;
}

UINT Authentication( struct _SS5ClientInfo *ci )
{
  register UINT idx;

  INT err  = ERR;
  INT err2 = ERR;

  char logString[256];

  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();

  memset(ci->Username,0,64);
  memset(ci->Password,0,64);

  strncpy(ci->Username,"\"\"",strlen("\"\""));

  if( ci->Method == NOAUTH ) {
    strncpy(ci->Username,"\"\"",strlen("\"\""));
    return OK;
  }
#ifdef SS5_USE_GSSAPI
  else if( (ci->Method == GSSAPI) ) {
   /*
    *    GSSAPI Authentication request
    */
    return( S5GSSApiSetup(ci) );
    
  }
#endif
  else if( (ci->Method == USRPWD) || (ci->Method == FAKEPWD)  || (ci->Method == S_USER_PWD) ) {

    switch( ci->Method ) {
      case USRPWD:
      case FAKEPWD:
      case S_USER_PWD:
       /*
        *    BASIC Authentication request
        */
        if( recv(ci->Socket,ci->Request,sizeof(ci->Request),0) <= 0 ) {
          ERRNO(pid)
          return ERR;
        }

        if (ci->Method == S_USER_PWD) {
         /* 
          *    Author: Raffaele De Lorenzo 
          *    Description: Start Secure Socks session. At the end return a User,Pwd 
          */
          if (ss5_secure_auth (ci->Socket, ci) != 0){
            SS5Modules.mod_logging.Logging("[ERRO] - ss5_secure_auth - Error in the secure phase\n");
            return ERR;
          }
        }
        break;
    }

   /*
    *    Check for buffer overflow
    */
    if( ((unsigned char)ci->Request[1] == 0) || ((unsigned char)ci->Request[1] >= sizeof(ci->Username)) ) {
      if( VERBOSE() )
        SS5Modules.mod_logging.Logging("[VERB] Buffer Overflow check during authentication (Null password?)");
      return ERR;
    }

    if( ((unsigned char)ci->Request[2+(unsigned char)ci->Request[1]] == 0)
        || ((unsigned char)ci->Request[2+(unsigned char)ci->Request[1]] >= sizeof(ci->Password)) ) { 
      if( VERBOSE() )
        SS5Modules.mod_logging.Logging("[VERB] Buffer Overflow check during authentication (Null password?)");
      return ERR;
    }

   /*
    *    Get credentials
    */
    for(idx = 0; idx < (unsigned char)ci->Request[1]; idx++)
      ci->Username[idx] = ci->Request[idx+2];
    ci->Username[idx] = '\0';

    for(idx = 0;idx < (unsigned char)ci->Request[2+(unsigned char)ci->Request[1]]; idx++)
      ci->Password[idx] = ci->Request[3+ci->Request[1]+idx];
    ci->Password[idx] = '\0';

    /*
     *    Look for username/password into authentication cache
     */
    if( THREADED() ) {
      if( SS5SocksOpt.AuthCacheAge ) {
        LOCKMUTEXAEC()
        err2 = GetAuthCache(ci->Username,ci->Password);
        UNLOCKMUTEXAEC()

        if( err2 == ERR_AUTHECACHE_EXPIRED ) {
          /*
           *    Update the entry into authentication cache
           */
          LOCKMUTEXAEC()
          UpdateAuthCache(ci->Username,ci->Password);
          UNLOCKMUTEXAEC()

          if( VERBOSE() ) {
            snprintf(logString,256 - 1,"[%u] [VERB] Cache authentication expired for user %s.",pid,ci->Username);
            SS5Modules.mod_logging.Logging(logString);
          }
        }
      }
    }
    
    if( err2 <= ERR ) {

      if( ci->Method != FAKEPWD ) {
        /*
         *    Evaluate how to handle basic autentication:
         *    1. using an External Program (EAP)     
         *    2. using PAM 
         *    3. using RADIUS
         *    4. using local file /etc/opt/ss5/ss5.passwd
         */
        switch( SS5SocksOpt.Authentication ) {
          case EAP_AUTHENTICATION:    err = S5AuthProgramCheck(ci, pid);    break;
  	  case PAM_AUTHENTICATION:    err = S5PamCheck(ci);                 break;
  	  case RADIUS_AUTHENTICATION: 
            err = S5RadiusAuth(ci, pid);          

          break;
          case FILE_AUTHENTICATION:   
            /*if( S5PwdFileOpen(pid) ) {*/
              err = S5PwdFileCheck(ci);
            /*  S5PwdFileClose(pid);
            }*/
          break;
        }
      }
      else {
        err = OK;
      }
  
      if( err ) {
        if( THREADED() ) {
          if( SS5SocksOpt.AuthCacheAge ) {
            /*
             * Add new entry into authentication cache
             */
            LOCKMUTEXAEC()
            AddAuthCache(ci->Username,ci->Password);
            UNLOCKMUTEXAEC()
            if( VERBOSE() ) {
              snprintf(logString,256 - 1,"[%u] [VERB] Cache authentication updated for user %s.",pid,ci->Username);
              SS5Modules.mod_logging.Logging(logString);
            }
          }
        }

        ci->Response[0] = 1; 
        ci->Response[1] = 0; /*    Basic success    */
        if( send(ci->Socket,ci->Response,sizeof(ci->Response),SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return ERR;
        }
        return OK;
      }
      else {
        ci->Response[0] = 1; 
        ci->Response[1] = 1; /*    Basic failed    */
    
        if( send(ci->Socket,ci->Response,sizeof(ci->Response),SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return ERR;
        }
      }
    }
    else if( THREADED() ) {
      if( SS5SocksOpt.AuthCacheAge ) {
        /*
         *    Entry in cache
         */
        if( VERBOSE() ) {
          snprintf(logString,256 - 1,"[%u] [VERB] Cache authentication verified for user %s.",pid,ci->Username);
          SS5Modules.mod_logging.Logging(logString);
        }

        ci->Response[0] = 1; 
        ci->Response[1] = 0; /*    Basic success    */
    
        if( send(ci->Socket,ci->Response,sizeof(ci->Response),SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return ERR;
        }
        return OK;
      }
    }
  }
  return ERR;
} 


UINT ListAuthenCache( UINT s)
{
  UINT count;

  struct _S5AuthCacheNode *node, *lnode;

  char buf[147];

  for(count = 0;count < MAXAUTHCACHELIST;count++) {
    if( (node=S5AuthCacheList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%64s\n%64s\n%16lu\n",lnode->Usr,lnode->Pwd,lnode->ttl);
          lnode=lnode->next;
        }

        if( send(s,buf,sizeof(buf),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      } while( lnode != NULL );
    }
  }
  return OK;
}


UINT SrvAuthentication( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  if( STREQ(sd->MethodRequest,"GET /list=AUTHCACHE HTTP/1.",sizeof("GET /list=AUTHCACHE HTTP/1.") - 1) ) {
    ListAuthenCache(ci->Socket);
    return OK;
  }
  return ERR;
}


/* ***************************** HASH for AUTHENTICATION CACHE **************************** */
inline UINT S5AuthCacheHash( char *u, char *p )
{
  register UINT idx;
  register UINT len;
  register long int hashVal = 0;
  char s[128];

  snprintf(s,sizeof(s) - 1,"%s%s",u,p);

  len=strlen(s);
  for(idx=0; idx<len;idx++)
    hashVal= 37*hashVal + s[idx];

  hashVal %= MAXAUTHCACHELIST;
  if(hashVal < 0)
    hashVal +=MAXAUTHCACHELIST;

  return hashVal;

}

UINT GetAuthCache(char *u, char *p)
{
  register UINT index;
  struct _S5AuthCacheNode *node;

    index=S5AuthCacheHash( u, p );

    if( S5AuthCacheList[index]!= NULL ) {
      node=S5AuthCacheList[index];
      do {
        if( STREQ(u,node->Usr,sizeof(node->Usr)) && STREQ(p,node->Pwd,sizeof(node->Pwd)) ) {
          if( node->ttl > time(NULL) )
            return OK;
          else
            return ERR_AUTHECACHE_EXPIRED;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}

UINT AddAuthCache(char *u, char *p )
{
  register UINT index;

  struct _S5AuthCacheNode *node, *prevnode;

  index=S5AuthCacheHash( u, p );

  if( S5AuthCacheList[index]== NULL ) {
    if( (S5AuthCacheList[index]=(struct _S5AuthCacheNode *)calloc(1,sizeof(struct _S5AuthCacheNode))) == NULL )
      return ERR;
    strncpy(S5AuthCacheList[index]->Usr,u,sizeof(S5AuthCacheList[index]->Usr));
    strncpy(S5AuthCacheList[index]->Pwd,p,sizeof(S5AuthCacheList[index]->Pwd));
    S5AuthCacheList[index]->ttl=(time(NULL) + SS5SocksOpt.AuthCacheAge);
    S5AuthCacheList[index]->next=NULL;
  }
  else {
    node=S5AuthCacheList[index];
    do {
      if( STREQ(u,node->Usr,sizeof(node->Usr)) && STREQ(p,node->Pwd,sizeof(node->Pwd)) ) 
        return ERR;

      prevnode=node;
      node=node->next;

    } while( node != NULL );

    if( (node=(struct _S5AuthCacheNode *)calloc(1,sizeof(struct _S5AuthCacheNode))) == NULL )
      return ERR;

    node->ttl=(time(NULL) + SS5SocksOpt.AuthCacheAge);
    strncpy(node->Usr,u,sizeof(S5AuthCacheList[index]->Usr));
    strncpy(node->Pwd,p,sizeof(S5AuthCacheList[index]->Pwd));
    node->next=NULL;
    
    prevnode->next=node;
  }
  return OK;
}

UINT UpdateAuthCache(char *u, char *p)
{
  register UINT index;
  struct _S5AuthCacheNode *node;

    index=S5AuthCacheHash( u, p );

    if( S5AuthCacheList[index]!= NULL ) {
      node=S5AuthCacheList[index];
      do {
        if( STREQ(u,node->Usr,sizeof(node->Usr)) && STREQ(p,node->Pwd,sizeof(node->Pwd)) ) {
          node->ttl=(time(NULL) + SS5SocksOpt.AuthCacheAge);
          return OK;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}



UINT FreeAuthCache( struct _S5AuthCacheNode **node )
{
  struct _S5AuthCacheNode *lnode;
  struct _S5AuthCacheNode *lnode_prev=NULL;

  lnode=*node;

  if( lnode != NULL ) {
    do {
      while( lnode->next != NULL ) {
        lnode_prev=lnode;
        lnode=lnode->next;
      }
      free(lnode);
      if( lnode_prev != NULL ) {
        lnode_prev->next=NULL;
        lnode=lnode_prev;
        lnode_prev=NULL;
      }
      else
        lnode=NULL;
    } while( (lnode) != NULL );
  }
  *node=NULL;
  
  return OK;

}

