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
 * $Id: SS5Mod_bandwidth.c, Ver 3.7 08-2008 10:00:00 Matteo Ricchetti Exp $
 */

#include"SS5Main.h"
#include <sys/time.h>
#include"SS5Mod_bandwidth.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m );

UINT InitModule( struct _module *m )
{
  m->Bandwidth       = Bandwidth;
  m->FreeBandTable   = FreeBandTable;
  m->UpdateBandTable = UpdateBandTable;
  m->AddBandTable    = AddBandTable;
  m->GetBandTableC   = GetBandTableC;
  m->CheckBandTableC = CheckBandTableC;
  m->GetBandTableB   = GetBandTableB;
  m->TransfBandTable = TransfBandTable;
  m->SrvBandwidth    = SrvBandwidth;

  return OK;
}

UINT Bandwidth( struct timeval btv, struct _SS5ProxyData *pd, struct _SS5Facilities *fa )
{
  static ULINT elapsedTime = 0,
                           bytesReceived = 0;

  register ULINT deltaElapsedTime;

  struct timeval betv;

  gettimeofday(&betv,NULL);

  deltaElapsedTime = (betv.tv_sec - btv.tv_sec)*(ULINT)1000000 + (betv.tv_usec - btv.tv_usec);

  elapsedTime += deltaElapsedTime;

  bytesReceived += pd->TcpRBufLen;

  if( bytesReceived > fa->Bandwidth) {
    usleep(((ULINT)1000000 - (elapsedTime  % (ULINT)1000000)));
    bytesReceived = 0;
    elapsedTime = 0;
  }
  return OK;
}


UINT SrvBandwidth( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  UINT count;
  
  char lncon[16],lband[16];

  char usr[64], srvResponse[116]="\0";

  if( STREQ(sd->MethodRequest,"GET /list=BANDWIDTH HTTP/1.",sizeof("GET /list=BANDWIDTH HTTP/1.") - 1) ) {
    /*
     *    Create response
     */
    for(count = 0;count < MAXBANDLIST;count++) {
      bzero(srvResponse,116);
      if( S5BandTableList[count] != NULL) {
        S5BrowseBandTable(srvResponse,S5BandTableList[count]);
        /*
         *    Send response
         */
        if( send(ci->Socket,srvResponse,sizeof(srvResponse),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      }
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /bandwidth=",sizeof("ADD /bandwidth=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"ADD /bandwidth=%64s\n%16s\n%16s\n\0",usr,lncon,lband);

    if( lband[0] == '-' ) 
      strncpy(lband,"0\0",sizeof("0\0"));

  
    if( AddBandTable(ONLINE, usr, atoi(lncon), atol(lband)) && (NBandwidthList < MAXBANDLIST) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0") - 1);
      NBandwidthList++;
    }
    else 
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0") - 1);

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /bandwidth=",sizeof("DEL /bandwidth=") - 1) ) {
    /*
     *    Create response
     */
    sscanf(sd->MethodRequest,"DEL /bandwidth=%64s\n%16s\n%16s\n\0",usr,lncon,lband);
  
    if( DelBandTable(usr) && (NBandwidthList > 0) ) {
      strncpy(srvResponse,"OK\0",sizeof("OK\0") - 1);
      NBandwidthList--;
    }
    else
      strncpy(srvResponse,"ERR\0",sizeof("ERR\0") - 1);

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  return ERR;
}



/* ***************************** HASH for BANDWIDTH TABLE **************************** */
inline UINT S5BandTableHash( char *u )
{
  register UINT idx;
  register UINT len;
  register long int hashVal = 0;
  char s[128];
  char t[128];

  idx=0;
  while( (t[idx]=tolower(u[idx])) )
    idx++;

  snprintf(s,sizeof(s) - 1,"%s",t);

  len=strlen(s);
  for(idx=0; idx<len;idx++)
    hashVal= 37*hashVal + s[idx];

  hashVal %= MAXAUTHCACHELIST;
  if(hashVal < 0)
    hashVal +=MAXAUTHCACHELIST;

  return hashVal;

}

UINT GetBandTableC(char *u)
{
  register UINT index;
  struct _S5BandTableNode *node;

    index=S5BandTableHash( u );

    if( S5BandTableList[index]!= NULL ) {
      node=S5BandTableList[index];
      do {
        if( STRCASEEQ(u,node->Usr,sizeof(node->Usr))) {
          return (node->NCon>0)?node->NCon:1;
        }
        node=node->next;
      } while(node != NULL );
    }

  return OK;
}

UINT CheckBandTableC(char *u)
{
  register UINT index;
  struct _S5BandTableNode *node;

    index=S5BandTableHash( u );

    if( S5BandTableList[index]!= NULL ) {
      node=S5BandTableList[index];
      do {
        if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
          if ( (node->NCon < node->LNCon) || (node->LNCon == 0) ) 
            return OK;
          else
            return ERR_LIMITFOUND;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}

ULINT GetBandTableB(char *u)
{
  register UINT index;
  struct _S5BandTableNode *node;

    index=S5BandTableHash( u );

    if( S5BandTableList[index]!= NULL ) {
      node=S5BandTableList[index];
      do {
        if( STRCASEEQ(u,node->Usr,sizeof(node->Usr))) {
          return node->LBand;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}

UINT AddBandTable(UINT ctx, char *u, int ln, ULINT lb )
{
  register UINT index;
  struct _S5BandTableNode *node, *prevnode;

  index=S5BandTableHash( u );

  if( ctx == OFFLINE )
    node=_tmp_S5BandTableList[index];
  else
    node=S5BandTableList[index];

  if( node == NULL ) {
    if( (node=(struct _S5BandTableNode *)calloc(1,sizeof(struct _S5BandTableNode))) == NULL )
      return ERR;

    strncpy(node->Usr,u,sizeof(_tmp_S5BandTableList[index]->Usr));
    node->NCon = 0;
    node->LNCon = ln;
    node->LBand = lb;
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5BandTableList[index]=node;
    else
      S5BandTableList[index]=node;
  }
  else {

    if( ctx == OFFLINE )
      node=_tmp_S5BandTableList[index];
    else
      node=S5BandTableList[index];

    do {
      if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
        return ERR;
      }
      prevnode=node;
      node=node->next;

    } while( node != NULL );
    
    if( (node=(struct _S5BandTableNode *)calloc(1,sizeof(struct _S5BandTableNode))) == NULL )
      return ERR;

    strncpy(node->Usr,u,sizeof(_tmp_S5BandTableList[index]->Usr));
    node->NCon = 0;
    node->LNCon = ln;
    node->LBand = lb;
    node->next=NULL;

    prevnode->next=node;
  }
  return OK;
}



UINT DelBandTable(char *u)
{
  register UINT index;
  struct _S5BandTableNode *node,*prevnode=NULL;

  index=S5BandTableHash( u );

  node=S5BandTableList[index];

  if( node == NULL )
    return ERR;

  if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
    if( node->next == NULL ) {

      free(node);
      S5BandTableList[index]=NULL;
      return OK;
    }
    else {
      S5BandTableList[index]=node->next;
      free(node);
      return OK;
    }
  }

  while( node->next != NULL ){
    prevnode=node;
    node=node->next;

    if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
      if( node->next != NULL ) 
        prevnode->next=node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;
    }
  }
  return OK;
}


UINT UpdateBandTable(char *u, int n)
{
  register UINT index;
  struct _S5BandTableNode *node;

  index=S5BandTableHash( u );

  if( S5BandTableList[index]!= NULL ) {
    node=S5BandTableList[index];
    do {
      if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
        node->NCon +=n;
        if( node->NCon < 0 )
          node->NCon =0;
        return OK;
      }
      node=node->next;
    } while(node != NULL );
  }

  return ERR;
}


UINT FreeBandTable( struct _S5BandTableNode **node )
{
  struct _S5BandTableNode *lnode;
  struct _S5BandTableNode *lnode_prev=NULL;

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

UINT TransfBandTable( struct _S5BandTableNode *node )
{
  struct _S5BandTableNode *lnode;
  int found=0;
  lnode=node;
  do {
    if(lnode != NULL ) {
      CopyBandTable(lnode->Usr,lnode->NCon);

      lnode=lnode->next;
      found++;
    }
  } while( lnode != NULL );

  return found;
}

UINT CopyBandTable(char *u, int n)
{
  register UINT index;
  struct _S5BandTableNode *node;

    index=S5BandTableHash( u );

    if( _tmp_S5BandTableList[index]!= NULL ) {
      node=_tmp_S5BandTableList[index];
      do {
        if( STRCASEEQ(u,node->Usr,sizeof(node->Usr)) ) {
          node->NCon =n;
          return OK;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}

UINT S5BrowseBandTable( char *buf, struct _S5BandTableNode *node )
{
  struct _S5BandTableNode *lnode;
  int found=0;

  lnode=node;
  do {
    if(lnode != NULL ) {
      snprintf(buf,116,"%64s\n%16u\n%16lu\n%16u\n",lnode->Usr,lnode->LNCon,lnode->LBand,lnode->NCon);
      lnode=lnode->next;
      found++;
    }
  } while( lnode != NULL );

  return found;
}

