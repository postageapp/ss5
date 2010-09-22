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

#include "SS5Main.h"
#include "SS5Mod_balance.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->AddVip  = AddVip;
  m->AddConn = S5AddConn2Real;
  m->RemoveConn = S5RemoveConn2Real;
  m->LoadBalancing = LoadBalancing;
  m->Balancing = Balancing;
  m->FreeConnectionTable = FreeConnectionTable;
  m->FreeAffinity = FreeAffinity;
  m->SrvBalancing = SrvBalancing;


  return OK;
}

UINT AddVip (char *real, UINT vid, UINT idx)
{
  S5AddReal2ConnectionTable(real, vid, idx);
 
  return OK;
}

UINT FreeConnectionTable (struct _S5ConnectionEntry *ce)
{
  free(ce);
 
  return OK;
}

UINT LoadBalancing( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri )
{
  struct in_addr s;
  struct in_addr d;

  UINT vid;
  UINT ttl_status;

  char logString[256];

  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();

  /*
   *    If affinity enabled, looks for affinity between src ip and dst ip
   *    before using balancing
   */
  if( SS5SocksOpt.Sticky ) {
    IFLINUX( inet_aton(ci->SrcAddr,&s); )
    IFSOLARIS( inet_pton(AF_INET, ci->SrcAddr, &s); )

    ttl_status = OK;
    vid = S5GetRealVid(ri->DstAddr);

    LOCKMUTEXCA()
    if( (d.s_addr = S5GetAffinity(s.s_addr,&ttl_status,vid)) == ERR ) {
      if( ttl_status == ERR ) {
        /*
         *    If age expired, remove affinity between src ip and dst ip
         */
        S5RemoveAffinity(s.s_addr,vid);

        if( VERBOSE() ) {
          snprintf(logString,256 - 1,"[%u] [VERB] Vip affinity expired for address %s.",pid,inet_ntoa(s));
          SS5Modules.mod_logging.Logging(logString);
        }
      }
      /*
       *    Balances with least connections
       */
      S5LeastConnectionReal(ri->DstAddr);

      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Balancing request on destination address %s.",pid,ri->DstAddr);
        SS5Modules.mod_logging.Logging(logString);
      }

      /*
       *    Setup affinity between src ip and dst ip
       */
      IFSOLARIS( inet_pton(AF_INET, ri->DstAddr, &d); )
      IFLINUX( inet_aton((const char *)ri->DstAddr,&d); )

      S5SetAffinity(s.s_addr,d.s_addr,vid);

      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Set VIP affinity for address %s.",pid,inet_ntoa(s));
        SS5Modules.mod_logging.Logging(logString);
      }
    }
    else {
      strncpy(ri->DstAddr,inet_ntoa(d),sizeof(ri->DstAddr));

      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Vip affinity verified for address %s.",pid,inet_ntoa(s));
        SS5Modules.mod_logging.Logging(logString);
      }
    }
    UNLOCKMUTEXCA()
  }
  else {
    /*
     *    Balances with least connections
     */
    S5LeastConnectionReal(ri->DstAddr);

    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] Balancing request on destination address %s.",pid,ri->DstAddr);
      SS5Modules.mod_logging.Logging(logString);
    }
  }
  
  return OK;
}

UINT ListVirtual( UINT s)
{
  UINT count;

  char buf[29];

  for(count = 0;count < NReal;count++) {
    if( S5ConnectionTable.S5ConnectionEntry[count] != NULL) {
      snprintf(buf,sizeof(buf),"%16s\n%5u\n%5u\n",S5ConnectionTable.S5ConnectionEntry[count]->Real,
                                                  S5ConnectionTable.S5ConnectionEntry[count]->Vid,
                                                  S5ConnectionTable.S5ConnectionEntry[count]->Connection);
      /*  Send response  */
      if( send(s,buf,sizeof(buf),0) == -1) {
        perror("Send err:");
        return ERR;
      }
    }
  }
  return OK;
}

UINT ListStikyCache( UINT s)
{
  UINT count;

  time_t currentAge;

  struct in_addr si,di;

  struct _S5StickyNode *node, *lnode;

  char buf[74], sa[16], da[16];

  for(count = 0;count < MAXSTICKYLIST; count++) {
    if( (node=S5StickyList[count]) != NULL) {
      lnode=node;
      do {
        if(lnode != NULL ) {
          si.s_addr = lnode->srcip;
          di.s_addr = lnode->dstip;

          strncpy(sa,inet_ntoa(si),sizeof(sa));
          strncpy(da,inet_ntoa(di),sizeof(da));

          currentAge = time(NULL);

          snprintf(buf,sizeof(buf), "%16s\n%5u\n%16s\n%16lu\n%16lu\n",sa,lnode->vid,da,lnode->ttl,currentAge);

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

UINT SrvBalancing( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  if( STREQ(sd->MethodRequest,"GET /list=VIRTUAL HTTP/1.",sizeof("GET /list=VIRTUAL HTTP/1.") - 1) ) {
    ListVirtual(ci->Socket);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"GET /list=STICKY HTTP/1.",sizeof("GET /list=STICKY HTTP/1.") - 1) ) {
    ListStikyCache(ci->Socket);
    return OK;
  }
  return ERR;
}


UINT S5LeastConnectionReal(char *s5application)
{
  register UINT i;
  register UINT j;

  UINT id1;
  UINT vid;
  UINT conn;

  LOCKMUTEXCT()
  /*
   *    Search for one real with the smaller number of connections
   */
  for(i = 0; i < NReal; i++) {
    if( STREQ(S5ConnectionTable.S5ConnectionEntry[i]->Real,s5application,strlen(s5application)) ) {
      id1  = i;
      vid  = S5ConnectionTable.S5ConnectionEntry[i]->Vid; 
      conn = S5ConnectionTable.S5ConnectionEntry[i]->Connection;

      for(j = 0; j<NReal; j++)
        if( S5ConnectionTable.S5ConnectionEntry[j]->Vid == vid )
	  if(S5ConnectionTable.S5ConnectionEntry[j]->Connection < conn ) {
            conn = S5ConnectionTable.S5ConnectionEntry[j]->Connection;
	    id1  = j;
	  }
      strncpy(s5application,S5ConnectionTable.S5ConnectionEntry[id1]->Real,sizeof(S5ConnectionTable.S5ConnectionEntry[id1]->Real) - 1);
      UNLOCKMUTEXCT()
      return OK;
    }
  }
  UNLOCKMUTEXCT()
  return ERR;
}

UINT S5AddReal2ConnectionTable(char *real, UINT vid, UINT idx)
{
  if( (S5ConnectionTable._tmp_S5ConnectionEntry[idx] = (struct _S5ConnectionEntry *)calloc(1,sizeof(struct _S5ConnectionEntry))) == NULL )
    return ERR;

  strncpy(S5ConnectionTable._tmp_S5ConnectionEntry[idx]->Real,real,strlen(real));
  S5ConnectionTable._tmp_S5ConnectionEntry[idx]->Vid = vid;
  S5ConnectionTable._tmp_S5ConnectionEntry[idx]->Connection = 0;

  return OK;
}

UINT S5GetRealVid(char *real)
{
  register UINT idx;

  for(idx = 0; idx < NReal; idx++)
    if( STREQ(S5ConnectionTable.S5ConnectionEntry[idx]->Real,real,strlen(real)) ) {
      return S5ConnectionTable.S5ConnectionEntry[idx]->Vid;
    }
  return ERR;
}

UINT S5AddConn2Real(char *real)
{
  register UINT idx;

  for(idx = 0; idx < NReal; idx++)
    if( STREQ(S5ConnectionTable.S5ConnectionEntry[idx]->Real,real,strlen(real)) ) {
      LOCKMUTEXCT()
      S5ConnectionTable.S5ConnectionEntry[idx]->Connection++;
      UNLOCKMUTEXCT()
      return OK;
    }
  return ERR;
}

UINT S5RemoveConn2Real(char *real)
{
  register UINT idx;

  for(idx = 0; idx < NReal; idx++)
    if( STREQ(S5ConnectionTable.S5ConnectionEntry[idx]->Real,real,strlen(real)) ) {
      if( S5ConnectionTable.S5ConnectionEntry[idx]->Connection ) {
        LOCKMUTEXCT()
        S5ConnectionTable.S5ConnectionEntry[idx]->Connection--;
        UNLOCKMUTEXCT()
      }
      return OK;
    }
  return ERR;
}

inline UINT S5StickyHash( ULINT srcip )
{
  return (srcip % MAXSTICKYLIST);
}

ULINT S5GetAffinity(ULINT srcip, UINT *ttl_status, UINT vid)
{
  UINT idx;

  struct _S5StickyNode *node;

  idx = S5StickyHash( srcip );

  if( S5StickyList[idx] == NULL )
    return ERR;
  else {
    node = S5StickyList[idx];

    do {
     if( (node->srcip == srcip)  && (node->vid == vid)) {
       if( node->ttl > time(NULL) ) {
         return node->dstip;
       }
       else {
	 *ttl_status = ERR;
         return ERR;
       }
     }  
     node = node->next;
    } while(node != NULL );
  }
  return ERR;
}

UINT S5SetAffinity(ULINT srcip, ULINT dstip, UINT vid )
{
  int idx;
  struct _S5StickyNode *node,*prevnode;
  struct in_addr s,d;

  s.s_addr = srcip;
  d.s_addr = dstip;

  idx=S5StickyHash( srcip );

  if( S5StickyList[idx] == NULL ) {
    if( (S5StickyList[idx] = (struct _S5StickyNode *)calloc(1,sizeof(struct _S5StickyNode))) == NULL )
      return ERR;
    S5StickyList[idx]->srcip = srcip;
    S5StickyList[idx]->dstip = dstip;
    S5StickyList[idx]->ttl = (time(NULL) + SS5SocksOpt.StickyAge);
    S5StickyList[idx]->vid = vid;
  }
  else {
    node=S5StickyList[idx];

    do {
      if( (node->srcip == srcip) && (node->dstip == dstip) ) {
        return ERR;
      }
      prevnode=node;
      node=node->next;

    } while( node != NULL );

    if( (node = (struct _S5StickyNode *)calloc(1,sizeof(struct _S5StickyNode))) == NULL )
      return ERR;
    node->srcip = srcip;
    node->dstip = dstip;
    node->ttl = (time(NULL) + SS5SocksOpt.StickyAge);
    node->vid = vid;
    node->next = NULL;

    prevnode->next=node;
  }
  return OK;
}

UINT S5RemoveAffinity(ULINT srcip, UINT vid)
{
  int idx;
  struct _S5StickyNode *node, *prevnode;

  idx = S5StickyHash( srcip );

  node = S5StickyList[idx];
  
  if( node == NULL )
    return ERR;

  if( (node->srcip == srcip) && (node->vid == vid) ) {
    if( node->next == NULL ) {
      free(node);
      S5StickyList[idx]=NULL;
      return OK;
    }
    else {
      S5StickyList[idx]=node->next;
      free(node);
      return OK;
    }
  }

  while(node->next != NULL ) {
    prevnode=node;
    node = node->next;

    if( (node->srcip == srcip) && (node->vid == vid) ) {
      if( node->next != NULL )
        prevnode->next = node->next;
      else
        prevnode->next=NULL;

      free(node);
      node=NULL;
     
      return OK;
    }   
  }
  return OK;
}

UINT Balancing( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{

  register UINT idx;

  struct in_addr s;
  struct in_addr d;

  time_t currentAge;

  struct _S5StickyNode *node;

  char *buf,
       sa[16],
       da[16];

  if( (buf = (char *)calloc(512,sizeof(char))) == NULL )
    return ERR;

  if( STREQ(sd->MethodRequest,"GET /balancing HTTP/1.",sizeof("GET /balancing HTTP/1.") - 1) ) {
    /*
     *     Create response
     */

    for(idx = 0; idx < NReal; idx++) {
      snprintf(buf,512 - 1, "%s\n%u\n%u\n",
        S5ConnectionTable.S5ConnectionEntry[idx]->Real,
        S5ConnectionTable.S5ConnectionEntry[idx]->Vid,
        S5ConnectionTable.S5ConnectionEntry[idx]->Connection);

      /*
       *    Send http response
       */
      if( send(ci->Socket,buf,512,SS5_SEND_OPT) == -1) {
        free(buf);
        return ERR;
      }
    }

    fcntl(ci->Socket,F_SETFL,O_NONBLOCK);
    recv(ci->Socket,buf,strlen(buf),0);
    free(buf);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"GET /sticky HTTP/1.",sizeof("GET /sticky HTTP/1.") - 1) ) {
    /*
     *     Create response
     */
    for(idx = 0; idx < 997; idx++) {
      node = S5StickyList[idx];

      while( node != NULL ) {

        s.s_addr = node->srcip;
        d.s_addr = node->dstip;

        strncpy(sa,inet_ntoa(s),sizeof(sa));
        strncpy(da,inet_ntoa(d),sizeof(da));

        currentAge = time(NULL);

        snprintf(buf,74, "%16s\n%5u\n%16s\n%16lu\n%16lu\n",sa,node->vid,da,node->ttl,currentAge);
        /*
         *    Send http response
         */
        if( send(ci->Socket,buf,74,SS5_SEND_OPT) == -1) {
          free(buf);
          return ERR;
        }

        node = node->next;
      }

    }
    free(buf);

    return OK;
  }

  free(buf);
  return ERR;
}

UINT FreeAffinity( struct _S5StickyNode **node )
{
  struct _S5StickyNode *lnode;
  struct _S5StickyNode *lnode_prev=NULL;

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

