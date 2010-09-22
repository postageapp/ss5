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


#include"SS5Main.h"
#include"SS5Mod_dump.h"
#include"SS5Utils.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->AddDump     = AddDump;
  m->FreeDump    = FreeDump;
  m->GetDump     = GetDump;
  m->OpenDump    = OpenDump;
  m->WritingDump = WritingDump;
  m->CloseDump   = CloseDump;
  m->SrvDump     = SrvDump;
  m->ListDump    = ListDump;

  return OK;
}

UINT ListDump( UINT s)
{
  UINT count;

  struct _S5DumpNode *node, *lnode;

  char buf[51];

  for(count = 0;count < MAXDUMPLIST; count++) {
    if( (node=S5DumpList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%16lu\n%2u\n%16lu\n%5u\n%5u\n%1u\n", lnode->DstAddr,lnode->Mask,lnode->DstPort,
             lnode->DstRangeMin,lnode->DstRangeMax,lnode->DumpMode);
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

UINT SrvDump( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  UINT dstMask;

  char da[64],dp[16],dm[1], srvResponse[16];

  if( STREQ(sd->MethodRequest,"GET /list=DUMP HTTP/1.",sizeof("GET /list=DUMP HTTP/1.") - 1) ) {
    ListDump(ci->Socket);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /dump=",sizeof("ADD /dump=") - 1) ) {

    sscanf(sd->MethodRequest,"ADD /dump=%64s\n%16s\n%1s\n",da,dp,dm);

    dstMask=S5GetNetmask(da);

    if( da[0] > 64 ) {
      if( AddDump(ONLINE,S5StrHash(da),S5GetRange(dp),atoi(dm),32-dstMask) && (NDumpList < MAXDUMPLIST)) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NDumpList++;
        SS5SocksOpt.IsDump = OK;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else {
      if( AddDump(ONLINE,inet_network(da),S5GetRange(dp),atoi(dm),32-dstMask) && (NDumpList < MAXDUMPLIST)) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NDumpList++;
        SS5SocksOpt.IsDump = OK;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"DEL /dump=",sizeof("DEL /dump=") - 1) ) {

    sscanf(sd->MethodRequest,"DEL /dump=%64s\n%16s\n%1s\n",da,dp,dm);

    dstMask=S5GetNetmask(da);

    if( da[0] > 64 ) {
      if( DelDump(S5StrHash(da),S5GetRange(dp),32-dstMask) && (NDumpList < MAXDUMPLIST)) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NDumpList++;
        SS5SocksOpt.IsDump = OK;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else {
      if( DelDump(inet_network(da),S5GetRange(dp),32-dstMask) && (NDumpList < MAXDUMPLIST)) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NDumpList++;
        SS5SocksOpt.IsDump = OK;
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }

    if( send(ci->Socket,srvResponse,strlen(srvResponse),0) == -1) {
      perror("Send err:");
      return ERR;
    }
    return OK;
  }

  return ERR;
}

UINT
WritingDump( FILE *df, struct _SS5ProxyData *pd, UINT dumpMode )
{
  char headerTitle[128];

  static UINT tx=0;
  static UINT rx=0;
  
  /*
   * TX
   */
  if( pd->Fd == 0 ) {
    if( (dumpMode == TX) || (dumpMode == RTX) ) {
      if( tx == 0 ) {
        sprintf(headerTitle,"\n------------------------------ TX SEGMENT ------------------------------\n");
        fwrite(headerTitle,sizeof(char),strlen(headerTitle),df);
        tx++;
        rx = 0;
      }

      fwrite(pd->Recv,sizeof(char),pd->TcpRBufLen,df);
    }
  } 
  /* RX */
  else {
    if( (dumpMode == RX) || (dumpMode == RTX) ) {
      if( rx == 0 ) {
        sprintf(headerTitle,"\n------------------------------ RX SEGMENT ------------------------------\n");
        fwrite(headerTitle,sizeof(char),strlen(headerTitle),df);
        rx++;
        tx = 0;
      }

      fwrite(pd->Recv,sizeof(char),pd->TcpRBufLen,df);
    }
  }
  return OK;
}

UINT 
OpenDump( FILE **df, struct _SS5ClientInfo *ci )
{
  char logString[128];
  char dumpFileName[64];
  char timeLog[32];

  pid_t pid;

  time_t now; 
  now = time(NULL);

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  strftime(timeLog,sizeof(timeLog),"%d-%b-%Y-%H-%M-%S",localtime(&now));

  sprintf(dumpFileName,"%s/ss5.%s.%u.%s.trc",S5TracePath,timeLog,pid,ci->Username);

  if( (*df = fopen(dumpFileName,"wb")) == NULL ) {
    ERRNO(pid)
    return ERR;
  }
  else
    return OK;
}

UINT 
CloseDump( FILE *df )
{

  fflush(df);
  fclose(df);
  
  return OK;
}

/* ***************************** HASH for DUMP **************************** */
inline UINT S5DumpHash( ULINT da, UINT dp )
{
  register int idx;
  register int len;

  register long int hashVal = 0;

  char s[32];

  snprintf(s,sizeof(s) - 1,"%lu%u",da,dp);

  len = strlen(s);
  for(idx = 0; idx < len; idx++)
    hashVal = 37*hashVal + s[idx];

  hashVal %= MAXDUMPLIST;
  if(hashVal < 0)
    hashVal += MAXDUMPLIST;

  return hashVal;

}

UINT GetDump(ULINT da, UINT dp, struct _SS5DumpInfo *di)
{
  register UINT index,nm;

  register ULINT n_da;

  struct _S5DumpNode *node;

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_da=((da >> nm) << nm);
    else
      n_da=0;

    index=S5DumpHash( n_da, dp );

    if( S5DumpList[index]!= NULL ) {
      node=S5DumpList[index];
      do {
        if( (node->DstAddr == n_da) && (node->Mask == (nm)) && (node->DstPort == dp) ) {
          di->DumpMode=node->DumpMode;
          return OK;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  for(nm=0;nm<=32;nm++) {
    if( nm < 32)
      n_da=((da >> nm) << nm);
    else
      n_da=0;

    index=S5DumpHash( n_da, 0 );

    if( S5DumpList[index]!= NULL ) {
      node=S5DumpList[index];
      do {
        if( (node->DstAddr == n_da) && (node->Mask == (nm)) && (dp >= node->DstRangeMin) && (dp <= node->DstRangeMax) ) {
          di->DumpMode=node->DumpMode;
          return OK;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  return ERR;
}

UINT DelDump(ULINT da, ULINT dp, UINT mask )
{
  int index;
  struct _S5DumpNode *node, *prevnode=NULL;

  if( dp > 65535 )
    index=S5DumpHash( da, 0 );
  else
    index=S5DumpHash( da, dp );


  node=S5DumpList[index];

  if( node == NULL )
    return ERR;

  if( (node->DstAddr == da) && (node->Mask == mask) && (dp == node->DstPort) ) {
    if( node->next == NULL ) {

      free(node);
      S5DumpList[index]=NULL;
      return OK;
    }
    else {
      S5DumpList[index]=node->next;
      free(node);
      return OK;
    }
  }

  while( node->next != NULL ) {
    prevnode=node;
    node=node->next;

    if( (node->DstAddr == da) && (node->Mask == mask) && (dp == node->DstPort) ) {
      if( node->next != NULL )
        prevnode->next=node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;

      return OK;
    }
  }
  return ERR;
}


UINT AddDump(UINT ctx, ULINT da, ULINT dp, UINT dumpMode, UINT mask )
{
  int index;
  struct _S5DumpNode *node, *prevnode;

  if( dp > 65535 )
    index=S5DumpHash( da, 0 );
  else
    index=S5DumpHash( da, dp );

  if( ctx == OFFLINE )
    node=_tmp_S5DumpList[index];
  else
    node=S5DumpList[index];

  if( node == NULL ) {
    if( (node=(struct _S5DumpNode *)calloc(1,sizeof(struct _S5DumpNode))) == NULL )
      return ERR;

    node->Mask=mask;
    node->DstAddr=da;

    if( dp > 65535 ) {
      node->DstPort=dp;
      node->DstRangeMax=dp;
      node->DstRangeMax >>= 16;
      node->DstRangeMax <<= 16;
      node->DstRangeMin = dp - node->DstRangeMax;
      node->DstRangeMax >>= 16;

    }
    else
      node->DstPort=dp;

    node->DumpMode=dumpMode;
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5DumpList[index]=node;
    else
      S5DumpList[index]=node;
  }
  else {
    if( ctx == OFFLINE )
      node=_tmp_S5DumpList[index];
    else
      node=S5DumpList[index];

    do {
      if( (node->DstAddr == da) && (node->Mask == mask) && (node->DstPort == dp) ) {
        return ERR;
      }
      prevnode=node;
      node=node->next;

    } while(node != NULL );

    if( (node=(struct _S5DumpNode *)calloc(1,sizeof(struct _S5DumpNode))) == NULL )
      return ERR;

    node->Mask=mask;
    node->DstAddr=da;

  if( dp > 65535 ) {
      node->DstPort=dp;
      node->DstRangeMax=dp;
      node->DstRangeMax >>= 16;
      node->DstRangeMax <<= 16;
      node->DstRangeMin = dp - node->DstRangeMax;
      node->DstRangeMax >>= 16;
    }
    else
      node->DstPort=dp;

    node->DumpMode=dumpMode;
    node->next=NULL;

    prevnode->next=node;
  }
  return OK;
}

UINT FreeDump( struct _S5DumpNode **node )
{
  struct _S5DumpNode *lnode;
  struct _S5DumpNode *lnode_prev=NULL;

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

