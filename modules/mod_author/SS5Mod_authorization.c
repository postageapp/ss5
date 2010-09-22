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
#include"SS5Mod_authorization.h"
#include"SS5OpenLdap.h"
#ifdef SS5_USE_MYSQL
#include"SS5MySql.h"
#include<mysql/mysql.h>
#endif
#include"SS5Utils.h"

#define _XOPEN_SOURCE /* glibc2 needs this */

#ifdef SOLARIS
  #include<lber.h>
#endif

#include<ldap.h>

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->PreAuthorization  = PreAuthorization;
  m->PostAuthorization = PostAuthorization;
  m->AddAcl  = AddAcl;
  m->FreeAcl = FreeAcl;
  m->GetAcl  = GetAcl;
  m->FreeAuthoCache = FreeAuthoCache;
  m->SrvAuthorization  = SrvAuthorization;
  m->UpdateAuthoCache  = UpdateAuthoCache;

  return OK;
}

UINT PreAuthorization( struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Facilities *fa )
{
  UINT i,l,me;

  INT err;

  INT err2 = ERR;

  pid_t pid;

  char logString[256];

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();

  strncpy(fa->Group,ci->Username,sizeof(fa->Group));
  STRSCAT(fa->Group,"\0");

  if( THREADED() ) {
    if( SS5SocksOpt.AuthoCacheAge ) {

      /*
       *  Look for permit line into authorization cache
       */
      LOCKMUTEXAC()

// TEST FTP FIXUP
  if( (err2=GetAuthoCache(ci->SrcAddr,ri->DstAddr,21,ci->Username,fa,0)) == (OK+100) )
  ;
  else
// END TEST FTP FIXUP
      err2 = GetAuthoCache(ci->SrcAddr,ri->DstAddr,ri->DstPort,ci->Username,fa,1);

      UNLOCKMUTEXAC()
      if( err2 == ERR_AUTHOCACHE_EXPIRED ) {
        /*
         * Update the entry into authorization cache
         */
        LOCKMUTEXAC()
        UpdateAuthoCache(ci->SrcAddr,ri->DstAddr,ri->DstPort,ci->Username,0);
        UNLOCKMUTEXAC()

        if( VERBOSE() ) {
          snprintf(logString,128,"[%u] [VERB] Cache authorization  expired for user %s.",pid,ci->Username);
          SS5Modules.mod_logging.Logging(logString);
        }
      }
    }
  }
  
  if( err2 <= ERR ) {
    switch( ri->Cmd ) {
      case CONNECT:
        if( ri->ATyp == DOMAIN )
          err = GetAcl(inet_network(ci->SrcAddr),ci->SrcPort,S5StrHash(ri->DstAddr),ri->DstPort,fa,&me);
        else 
          err = GetAcl(inet_network(ci->SrcAddr),ci->SrcPort,inet_network(ri->DstAddr),ri->DstPort,fa,&me);
        if( err >= ERR ) {

          if( ( me == ci->Method ) || ( me == NOAUTH ) || ( me == FAKEPWD ) ) {
            if( THREADED() ) {
              if( SS5SocksOpt.AuthoCacheAge ) {
                /*
                 * Add new entry into authorization cache
                 */
                LOCKMUTEXAC()
                AddAuthoCache(ci->SrcAddr,ri->DstAddr,ri->DstPort,ci->Username,fa);
                UNLOCKMUTEXAC()
                if( VERBOSE() ) {
                  snprintf(logString,128,"[%u] [VERB] Cache  autorization  updated for user %s.",pid,ci->Username);
                  SS5Modules.mod_logging.Logging(logString);
                }
              }
            }
            return OK;
          }
        }
      break;
      case BIND:
        if( ri->ATyp == DOMAIN )
          err = GetAcl(S5StrHash(ri->DstAddr),ri->DstPort,inet_network(ci->SrcAddr),ci->SrcPort,fa,&me);
        else
          err = GetAcl(inet_network(ri->DstAddr),ri->DstPort,inet_network(ci->SrcAddr),ci->SrcPort,fa,&me);
  
        if( err >= ERR ) {
          if( ( me == ci->Method ) || ( me == NOAUTH ) || ( me == FAKEPWD ) ) {
            if( THREADED() ) {
              if( SS5SocksOpt.AuthoCacheAge ) {
                /*
                 * Add new entry into authorization cache
                 */
                LOCKMUTEXAC()
                AddAuthoCache(ci->SrcAddr,ri->DstAddr,ri->DstPort,ci->Username,fa);
                UNLOCKMUTEXAC()
                if( VERBOSE() ) {
                  snprintf(logString,128,"[%u] [VERB] Cache  autorization  updated for user %s.",pid,ci->Username);
                  SS5Modules.mod_logging.Logging(logString);
                }
              }
            }
            return OK;
          }
        }
      break;
    }
  }
  else if( THREADED() ) {
    if( SS5SocksOpt.AuthoCacheAge ) {
      /*
       * Entry in cache
       */
      if( VERBOSE() ) {
        snprintf(logString,128,"[%u] [VERB] Cache authorization  verified for user %s.",pid,ci->Username);
        SS5Modules.mod_logging.Logging(logString);
      }

      return OK;
    }
  }

  return ERR;
}

UINT PostAuthorization(  struct _SS5ClientInfo *ci,
                             struct _SS5RequestInfo *ri, struct _SS5Facilities *fa )
{
  UINT i,l,me;

  INT err;

  strncpy(fa->Group,ci->Username,sizeof(fa->Group));
  STRSCAT(fa->Group,"\0");

  switch( ri->Cmd ) {
    case UDP_ASSOCIATE:
      if( ri->ATyp == DOMAIN )
        err = GetAcl(inet_network(ci->udpSrcAddr),ci->udpSrcPort,S5StrHash(ri->udpDstAddr),ri->udpDstPort,fa,&me);
      else 
        err = GetAcl(inet_network(ci->udpSrcAddr),ci->udpSrcPort,inet_network(ri->udpDstAddr),ri->udpDstPort,fa,&me);
      if( err >= ERR ) {
        if( ( me == ci->Method ) || ( me == NOAUTH ) || ( me == FAKEPWD ) ) {
          return OK;
        }
    }
    break;
  }
  return ERR;
}

UINT ListAutho( UINT s )
{
  UINT count;

  struct _S5AclNode *lnode, *node;

  char buf[553];

  for(count = 0;count < MAXACLLIST; count++) {
    if( (node=S5AclList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%3u\n%16lu\n%64s\n%2u\n%16lu\n%5u\n%5u\n%16lu\n%64s\n%2u\n%16lu\n%5u\n%5u\n%16s\n%256s\n%16lu\n%10s\n%1u\n", 
                   lnode->Method,lnode->SrcAddr,lnode->SrcAddrFqdn,lnode->SrcMask,lnode->SrcPort,lnode->SrcRangeMin,lnode->SrcRangeMax,
                   lnode->DstAddr,lnode->DstAddrFqdn,lnode->DstMask,lnode->DstPort,lnode->DstRangeMin,lnode->DstRangeMax,
                   lnode->Fixup,lnode->Group,lnode->Bandwidth,lnode->ExpDate,lnode->Type);

          lnode=lnode->next;
        }

        /* Send response to SS5SRV */
        if( send(s,buf,sizeof(buf),0) == -1) {
          perror("Send err:");
          return ERR;
        }
      } while( lnode != NULL );
    }
  }
  return OK;
}

UINT ListAuthoCache( UINT s )
{
  UINT count;

  struct _S5AuthoCacheNode *lnode, *node;

  char buf[230];

  for(count = 0;count < MAXAUTHOCACHELIST; count++) {
    if( (node=S5AuthoCacheList[count]) != NULL) {

      lnode=node;
      do {
        if(lnode != NULL ) {
          snprintf(buf,sizeof(buf),"%64s\n%5u\n%64s\n%5u\n%64s\n%16lu\n%5u\n",lnode->Sa,lnode->Sp,lnode->Da,lnode->Dp,lnode->Us,lnode->ttl,lnode->Flg);
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

UINT SrvAuthorization( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  UINT type,
               method,
               srcMask,
               dstMask;

  char me[1],sa[64],sp[16],da[64],dp[16],fu[16],grp[256],ba[16],ed[10];

  struct _SS5Facilities fa;

  char srvResponse[544];

  if( STREQ(sd->MethodRequest,"GET /list=AUTHORIZATION HTTP/1.",sizeof("GET /list=AUTHORIZATION HTTP/1.") - 1) ) {
    ListAutho(ci->Socket);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"GET /list=AUTHOCACHE HTTP/1.",sizeof("GET /list=AUTHOCACHE HTTP/1.") - 1) ) {
    ListAuthoCache(ci->Socket);
    return OK;
  }
  else if( STREQ(sd->MethodRequest,"ADD /permit=",sizeof("ADD /permit=") - 1)  || STREQ(sd->MethodRequest,"ADD /deny=",sizeof("ADD /deny=") - 1) ) {

    if( STREQ(sd->MethodRequest,"ADD /permit=",sizeof("ADD /permit=") - 1) ) {
      sscanf(sd->MethodRequest,"ADD /permit=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",me,sa,sp,da,dp,fu,grp,ba,ed);
      type=PERMIT;
    }
    else {
      sscanf(sd->MethodRequest,"ADD /deny=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",me,sa,sp,da,dp,fu,grp,ba,ed);
      type=DENY;
    }

    switch(me[0]) {
      case '-':    method=NOAUTH;    break;
      case 'u':    method=USRPWD;    break;
      case 'n':    method=FAKEPWD;   break;
      case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
      case 'k':    method=GSSAPI;      break;
#endif
      default:     SS5Modules.mod_logging.Logging("[ERRO] Method unknown in permit line.");    return ERR;    break;
    }

    if( ba[0] == '-' )
      strncpy(ba,"0\0",2);

    strncpy(fa.Fixup,fu,sizeof(fa.Fixup));
    strncpy(fa.Group,grp,sizeof(fa.Group));
    fa.Bandwidth=atoi(ba);
    strncpy(fa.ExpDate,ed,sizeof(fa.ExpDate));

    srcMask=S5GetNetmask(sa);
    dstMask=S5GetNetmask(da);

    if( (sa[0] > 64) && (da[0] >64) ) {
      if( AddAcl(ONLINE, type,S5StrHash(sa),sa, S5GetRange(sp), S5StrHash(da),da,S5GetRange(dp),32-srcMask,32-dstMask,method,&fa)  &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else if( da[0] >64 ) {
      if( AddAcl(ONLINE, type,inet_network(sa),"-", S5GetRange(sp), S5StrHash(da),da,S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else if ( sa[0] > 64 ) {
      if( AddAcl(ONLINE,type,S5StrHash(sa),sa,S5GetRange(sp), inet_network(da),"-",S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else {
      if( AddAcl(ONLINE,type,inet_network(sa),"-", S5GetRange(sp),inet_network(da),"-",S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
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
  else if( STREQ(sd->MethodRequest,"DEL /permit=",sizeof("DEL /permit=") - 1) || STREQ(sd->MethodRequest,"DEL /deny=",sizeof("DEL /deny=") - 1) ) {

    if( STREQ(sd->MethodRequest,"DEL /permit=",sizeof("DEL /permit=") - 1) ) {
      sscanf(sd->MethodRequest,"DEL /permit=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",me,sa,sp,da,dp,fu,grp,ba,ed);
      type=PERMIT;
    }
    else {
      sscanf(sd->MethodRequest,"DEL /deny=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",me,sa,sp,da,dp,fu,grp,ba,ed);
      type=DENY;
    }

    switch(me[0]) {
      case '-':    method=NOAUTH;    break;
      case 'u':    method=USRPWD;    break;
      case 'n':    method=FAKEPWD;   break;
      case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
      case 'k':    method=GSSAPI;      break;
#endif
      default:     SS5Modules.mod_logging.Logging("[ERRO] Method unknown in permit line.");    return ERR;    break;
    }

    if( ba[0] == '-' )
      strncpy(ba,"0\0",2);

    strncpy(fa.Fixup,fu,sizeof(fa.Fixup));
    strncpy(fa.Group,grp,sizeof(fa.Group));
    fa.Bandwidth=atoi(ba);
    strncpy(fa.ExpDate,ed,sizeof(fa.ExpDate));

    srcMask=S5GetNetmask(sa);
    dstMask=S5GetNetmask(da);

    if( (sa[0] > 64) && (da[0] >64) ) {
      if( DelAcl(PERMIT,S5StrHash(sa),sa, S5GetRange(sp), S5StrHash(da),da,S5GetRange(dp),32-srcMask,32-dstMask,method,&fa)  &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else if( da[0] >64 ) {
      if( DelAcl(PERMIT,inet_network(sa),"-", S5GetRange(sp), S5StrHash(da),da,S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else if ( sa[0] > 64 ) {
      if( DelAcl(PERMIT,S5StrHash(sa),sa,S5GetRange(sp), inet_network(da),"-",S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
      }
      else
        strncpy(srvResponse,"ERR\0",sizeof("ERR\0"));
    }
    else {
      if( DelAcl(PERMIT,inet_network(sa),"-", S5GetRange(sp),inet_network(da),"-",S5GetRange(dp),32-srcMask,32-dstMask,method,&fa) &&
          (NAclList < MAXACLLIST) ) {
        strncpy(srvResponse,"OK\0",sizeof("OK\0"));
        NAclList++; 
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

inline UINT FileCheck( char *group, char *user )
{
  FILE *groupFile;

  UINT i,l;

  pid_t pid;

  char groupFileName[512];
  char userName[64];

  char logString[128];

   /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  if( SS5SocksOpt.Profiling == FILE_PROFILING ) {
    strncpy(groupFileName,S5ProfilePath,sizeof(groupFileName));
    STRSCAT(groupFileName,"/");
    STRSCAT(groupFileName,group);

    if( (groupFile = fopen(groupFileName,"r")) == NULL ) {
      ERRNO(pid)
      return ERR;
    }

    /*
     *    Check for username into configuration file for access profile
     */
    while( fscanf(groupFile,"%64s",userName) != EOF ) {
      if( userName[0] != '#' )
        if( STRCASEEQ(userName,user,64) ) {
          fclose(groupFile);
          return OK;
        }
    }
    fclose(groupFile);
    return ERR;
  }
  return ERR;
}

UINT S5CheckexpDate(char *expdate)
{
  time_t t;
  struct tm *currentDate;
  struct tm tm;

  char ps[128];

  if( expdate[0] == '-' )
    return OK;

  strncpy(ps,expdate,sizeof(ps));
  strncat(ps," 00:00:00",sizeof(ps));
  strptime(ps, "%d-%m-%Y %H:%M:%S", &tm);

  t=time(NULL);
  currentDate=gmtime(&t);

  if( tm.tm_year < currentDate->tm_year )
    return ERR;
  else if( tm.tm_year > currentDate->tm_year )
    return OK;
  else if( tm.tm_mon < currentDate->tm_mon )
    return ERR;
  else if( tm.tm_mon > currentDate->tm_mon )
    return OK;
  else if( tm.tm_mday < currentDate->tm_mday )
    return ERR;
  else
    return OK;
}

UINT S5CheckPort(char *port, UINT s5port)
{
  register UINT idx1;
  register UINT idx2;

  UINT p1 = 0;
  UINT p2 = 0;
  UINT len;

  char s1[6];
  char s2[6];

  len = strlen(port);
  for(idx1 = 0; (port[idx1]) != '-' && (idx1 < len); idx1++)
    s1[idx1] = port[idx1];
  if( (p1 = atoi(s1)) > 65535 )
          return ERR;
  idx1++;
  for(idx2 = 0; idx1 < len; idx2++, idx1++)
          s2[idx2] = port[idx1];
  if( (p2 = atoi(s2)) > 65535 )
          return ERR;
  if( p2 ) {
    if( p2 < p1 )
      return ERR;
    else if( s5port < p1 || s5port > p2 )
      return ERR;
  }
  else if( p1 != s5port )
    return ERR;

  return OK;
}


/* ******************************** HASH for ACL ******** **************************** */
inline UINT AclHash( ULINT sa, ULINT da, UINT dp )
{
  register UINT idx;
  register UINT len;

  register long int hashVal = 0;

  char s[256];

  snprintf(s,sizeof(s) - 1,"%lu%lu%u",sa,da,dp);

  len = strlen(s);
  for(idx = 0; idx < len; idx++)
    hashVal = 37*hashVal + s[idx];

  hashVal %= MAXACLLIST;
  if(hashVal < 0)
    hashVal += MAXACLLIST;

  return hashVal;
}

INT GetAcl(ULINT sa, UINT sp, ULINT da, UINT dp, struct _SS5Facilities *fa, UINT *me)
{
  register UINT index;
  register UINT srcnm;
  register UINT dstnm;

  register ULINT n_sa;
  register ULINT n_da;

  UINT err = ERR;

  struct _S5AclNode *node;

  /*
   * 1° hash cicle: check <SrcIP/Net> <DstIP> <DstPort>
   */
  for(srcnm=0;srcnm<=32;srcnm++) {
    if( srcnm < 32)
      n_sa=((sa >> srcnm) << srcnm);
    else
      n_sa=0;
    index=AclHash( n_sa, da, dp );

    if( S5AclList[index]!= NULL ) {
      node=S5AclList[index];
      do {
        if( (node->SrcAddr == n_sa) && (node->SrcMask == srcnm) && (node->DstAddr == da) && (node->DstPort == dp) ) {
          if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
            if( S5CheckexpDate(node->ExpDate) ) {
             if( node->Group[0] != '-' ) {
               /*
                * Look for username into group (file or directory) defined in permit line
                */
               if( SS5SocksOpt.Profiling == FILE_PROFILING )
                 err=FileCheck(node->Group,fa->Group);
               else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                 err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
               else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                 err=MySqlCheck(node->Group,fa->Group);
#endif
               if( err ) {
                 *me=node->Method;
                 strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                 fa->Bandwidth=node->Bandwidth;
                 if(node->Type == PERMIT ) {
                   return OK;
                 }
                 return ERR_DENY;
               }
             }
             else {
               *me=node->Method;
               strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
               fa->Bandwidth=node->Bandwidth;
               if(node->Type == PERMIT ) {
                 return OK;
               }
               return ERR_DENY;
             }
           }
          }
        }
        node=node->next;
      } while(node != NULL );
    }
  }
  /*
   * 2° hash cicle: check <SrcIP/Net> <DstIP> <0-65535 (DstPort)>
   */
  for(srcnm=0;srcnm<=32;srcnm++) {
    if( srcnm < 32)
      n_sa=((sa >> srcnm) << srcnm);
    else
      n_sa=0;
    index=AclHash( n_sa, da, 0 );

    if( S5AclList[index]!= NULL ) {
      node=S5AclList[index];
      do {
        if( (node->SrcAddr == n_sa) && (node->SrcMask == srcnm) && (node->DstAddr == da) && (dp >= node->DstRangeMin) && (dp <= node->DstRangeMax) ) {
          if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
            if( S5CheckexpDate(node->ExpDate) ) {
              if( node->Group[0] != '-' ) {
                /*
                 * Look for username into group (file or directory) defined in permit line
                 */
                if( SS5SocksOpt.Profiling == FILE_PROFILING )
                  err=FileCheck(node->Group,fa->Group);
                else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                  err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
                else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                  err=MySqlCheck(node->Group,fa->Group);
#endif
                if( err ) {
                  *me=node->Method;
                  strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                  fa->Bandwidth=node->Bandwidth;
                  if(node->Type == PERMIT )
                    return OK;
                  return ERR_DENY;
                }
              }
              else {
                *me=node->Method;
                strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                fa->Bandwidth=node->Bandwidth;
                if(node->Type == PERMIT ) {
                  return OK;
                }
                return ERR_DENY;
              }
            }
          }
        }
        node=node->next;
      } while(node != NULL );
    }
  }


  /*
   * 3° hash cicle: check <SrcIP> <DstIP/Net> <DstPort>
   */
  for(dstnm=0;dstnm<=32;dstnm++) {
    if( dstnm < 32)
      n_da=((da >> dstnm) << dstnm);
    else
      n_da=0;
    index=AclHash( sa, n_da, dp );

    if( S5AclList[index]!= NULL ) {
      node=S5AclList[index];
      do {
        if( (node->SrcAddr == sa) && (node->DstAddr == n_da) && (node->DstMask == dstnm) && (node->DstPort == dp) ) {
          if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
            if( S5CheckexpDate(node->ExpDate) ) {
              if( node->Group[0] != '-' ) {
                /*
                 * Look for username into group (file or directory) defined in permit line
                 */
                if( SS5SocksOpt.Profiling == FILE_PROFILING )
                  err=FileCheck(node->Group,fa->Group);
                else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                  err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
                else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                  err=MySqlCheck(node->Group,fa->Group);
#endif
                if( err ) {
                  *me=node->Method;
                  strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                  fa->Bandwidth=node->Bandwidth;
                  if(node->Type == PERMIT )
                    return OK;
                  return ERR_DENY;
                }
              }
              else {
                *me=node->Method;
                strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                fa->Bandwidth=node->Bandwidth;
                if(node->Type == PERMIT ) {
                  return OK;
                }
                return ERR_DENY;
              }
            }
          }
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  /*
   * 4° hash cicle: check <SrcIP> <DstIP/Net> <0-65535 (DstPort)>
   */
  for(dstnm=0;dstnm<=32;dstnm++) {
    if( dstnm < 32)
      n_da=((da >> dstnm) << dstnm);
    else
      n_da=0;
    index=AclHash( sa, n_da, 0 );

    if( S5AclList[index]!= NULL ) {
      node=S5AclList[index];
      do {
        if( (node->SrcAddr == sa) && (node->DstAddr == n_da) && (node->DstMask == dstnm) && (dp >= node->DstRangeMin) && (dp <= node->DstRangeMax) ) {
          if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
            if( S5CheckexpDate(node->ExpDate) ) {
              if( node->Group[0] != '-' ) {
                /*
                 * Look for username into group (file or directory) defined in permit line
                 */
                if( SS5SocksOpt.Profiling == FILE_PROFILING )
                  err=FileCheck(node->Group,fa->Group);
                else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                  err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
                else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                  err=MySqlCheck(node->Group,fa->Group);
#endif
                if( err ) {
                  *me=node->Method;
                  strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                  fa->Bandwidth=node->Bandwidth;
                  if(node->Type == PERMIT )
                    return OK;
                  return ERR_DENY;
                }
              }
              else {
                *me=node->Method;
                strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                fa->Bandwidth=node->Bandwidth;
                if(node->Type == PERMIT ) {
                  return OK;
                }
                return ERR_DENY;
              }
            }
          }
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  /*
   * 5° hash cicle: check <SrcIP/Net> <DstIP/Net> <DstPort>
   */
  for(dstnm=1;dstnm<=32;dstnm++) {
    if( dstnm < 32)
      n_da=((da >> dstnm) << dstnm);
    else
      n_da=0;

    for(srcnm=1;srcnm<=32;srcnm++) {
      if( srcnm < 32)
        n_sa=((sa >> srcnm) << srcnm);
      else
        n_sa=0;
      index=AclHash( n_sa, n_da, dp );

      if( S5AclList[index]!= NULL ) {
        node=S5AclList[index];
        do {
          if( (node->SrcAddr == n_sa) && (node->SrcMask == srcnm) && (node->DstAddr == n_da) && (node->DstMask == dstnm) && (node->DstPort == dp) ) {
            if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
              if( S5CheckexpDate(node->ExpDate) ) {
                if( node->Group[0] != '-' ) {
                  /*
                   * Look for username into group (file or directory) defined in permit line
                   */
                  if( SS5SocksOpt.Profiling == FILE_PROFILING )
                    err=FileCheck(node->Group,fa->Group);
                  else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                    err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
                  else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                    err=MySqlCheck(node->Group,fa->Group);
#endif
                  if( err ) {
                    *me=node->Method;
                    strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                    fa->Bandwidth=node->Bandwidth;
                    if(node->Type == PERMIT )
                      return OK;

                    return ERR_DENY;
                  }
                }
                else {
                  *me=node->Method;
                  strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                  fa->Bandwidth=node->Bandwidth;
                  if(node->Type == PERMIT ) {
                    return OK;
                  }
                  return ERR_DENY;
                }
              }
            }
          }
          node=node->next;
        } while(node != NULL );
      }
    }
  }
  /*
   * 6° hash cicle: check <SrcIP/Net> <DstIP/Net> <DstPort>
   */
  for(dstnm=1;dstnm<=32;dstnm++) {
    if( dstnm < 32)
      n_da=((da >> dstnm) << dstnm);
    else
      n_da=0;

    for(srcnm=1;srcnm<=32;srcnm++) {
      if( srcnm < 32)
        n_sa=((sa >> srcnm) << srcnm);
      else
        n_sa=0;
      index=AclHash( n_sa, n_da, 0 );

      if( S5AclList[index]!= NULL ) {
        node=S5AclList[index];
        do {
          if( (node->SrcAddr == n_sa) && (node->SrcMask == srcnm) && (node->DstAddr == n_da) && (node->DstMask == dstnm) && (dp >= node->DstRangeMin) && (dp <= node->DstRangeMax) ) {
            if( ((sp >= node->SrcRangeMin) && (sp <= node->SrcRangeMax)) || (node->SrcPort == sp) ) {
              if( S5CheckexpDate(node->ExpDate) ) {
                if( node->Group[0] != '-' ) {
                  /*
                   * Look for username into group (file or directory) defined in permit line
                   */
                  if( SS5SocksOpt.Profiling == FILE_PROFILING )
                    err=FileCheck(node->Group,fa->Group);
                  else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
                    err=DirectoryCheck(node->Group,fa->Group);
#ifdef SS5_USE_MYSQL
                  else if( SS5SocksOpt.Profiling == MYSQL_PROFILING )
                    err=MySqlCheck(node->Group,fa->Group);
#endif
                  if( err ) {
                    *me=node->Method;
                    strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                    fa->Bandwidth=node->Bandwidth;
                    if(node->Type == PERMIT )
                      return OK;
                    return ERR_DENY;
                  }
                }
                else {
                  *me=node->Method;
                  strncpy(fa->Fixup,node->Fixup,sizeof(fa->Fixup));
                  fa->Bandwidth=node->Bandwidth;
                  if(node->Type == PERMIT ) {
                    return OK;
                  }
                  return ERR_DENY;
                }
              }
            }
          }
          node=node->next;
        } while(node != NULL );
      }
    }
  }
  return ERR_NOACLFOUND;
}

UINT AddAcl(UINT ctx, UINT type, ULINT sa, char sfqdn[64],ULINT sp, ULINT da, char dfqdn[64],ULINT dp, UINT srcmask, UINT dstmask, UINT method, struct _SS5Facilities *fa)
{
  int index;
  struct _S5AclNode *node, *prevnode;

  if( dp > 65535 ) 
    index=AclHash( sa, da, 0 );
  else
    index=AclHash( sa, da, dp );


  if( ctx == OFFLINE )
    node=_tmp_S5AclList[index];
  else
    node=S5AclList[index];

  if( node== NULL ) {
    if( (node=(struct _S5AclNode *)calloc(1,sizeof(struct _S5AclNode))) == NULL )
      return ERR;

    node->SrcAddr=sa;
    strncpy(node->SrcAddrFqdn,sfqdn,sizeof(node->SrcAddrFqdn));
    node->Type=type;


    if( sp > 65535 ) {
      node->SrcPort=sp;
      node->SrcRangeMax=sp;
      node->SrcRangeMax >>= 16;
      node->SrcRangeMax <<= 16;
      node->SrcRangeMin = sp - node->SrcRangeMax;
      node->SrcRangeMax >>= 16;
    }
    else
      node->SrcPort=sp;


    node->SrcMask=srcmask;
    node->DstAddr=da;
    strncpy(node->DstAddrFqdn,dfqdn,sizeof(node->DstAddrFqdn));

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


    node->DstMask=dstmask;
    node->Method=method;
    strncpy(node->Fixup,fa->Fixup,sizeof(fa->Fixup));
    strncpy(node->Group,fa->Group,sizeof(fa->Group));
    node->Bandwidth=fa->Bandwidth;
    strncpy(node->ExpDate,fa->ExpDate,sizeof(fa->ExpDate));
    node->next=NULL;

    if( ctx == OFFLINE )
      _tmp_S5AclList[index]=node;
    else
      S5AclList[index]=node;

  }
  else {

    if( ctx == OFFLINE )
      node=_tmp_S5AclList[index];
    else
      node=S5AclList[index];

    do {
      if( (node->SrcAddr == sa) && (node->SrcMask == srcmask) && (node->DstAddr == da) && (node->DstMask == dstmask) )
        if( (node->DstPort == dp) && (node->SrcPort == sp))  {
          return ERR;
        }

      prevnode=node;
      node=node->next;

    } while( node != NULL );

    if( (node=(struct _S5AclNode *)calloc(1,sizeof(struct _S5AclNode))) == NULL )
      return ERR;


    node->SrcAddr=sa;
    strncpy(node->SrcAddrFqdn,sfqdn,sizeof(node->SrcAddrFqdn));
    node->Type=type;

    if( sp > 65535 ) {
      node->SrcPort=sp;
      node->SrcRangeMax=sp;
      node->SrcRangeMax >>= 16;
      node->SrcRangeMax <<= 16;
      node->SrcRangeMin = sp - node->SrcRangeMax;
      node->SrcRangeMax >>= 16;
    }
    else
      node->SrcPort=sp;

    node->SrcMask=srcmask;
    node->DstAddr=da;
    strncpy(node->DstAddrFqdn,dfqdn,sizeof(node->DstAddrFqdn));

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

    node->DstMask=dstmask;
    node->Method=method;
    strncpy(node->Fixup,fa->Fixup,sizeof(fa->Fixup));
    strncpy(node->Group,fa->Group,sizeof(fa->Group));
    node->Bandwidth=fa->Bandwidth;
    strncpy(node->ExpDate,fa->ExpDate,sizeof(fa->ExpDate));
    node->next=NULL;

    prevnode->next=node;
  }

  return OK;
}


UINT DelAcl(UINT type, ULINT sa, char sfqdn[64],ULINT sp, ULINT da, char dfqdn[64],ULINT dp, UINT srcmask, UINT dstmask, UINT method, struct _SS5Facilities *fa)
{
  int index;
  struct _S5AclNode *node, *prevnode=NULL;

  if( dp > 65535 ) 
    index=AclHash( sa, da, 0 );
  else
    index=AclHash( sa, da, dp );

  node=S5AclList[index];

  if( node == NULL )
    return ERR;

  if( (node->SrcAddr == sa) && (node->SrcMask == srcmask) && (node->DstAddr == da) && (node->DstMask == dstmask) ) {
    if( (node->Type == type) && (node->DstPort == dp) && (node->SrcPort == sp))  {
      if( node->next == NULL ) {
      
        free(node);
        S5AclList[index]=NULL;
        return OK;
      }
      else {
        S5AclList[index]=node->next;
        free(node);
        return OK;
      }
    }
  }

  while( node->next != NULL ) {
    prevnode=node;
    node=node->next;

    if( (node->SrcAddr == sa) && (node->SrcMask == srcmask) && (node->DstAddr == da) && (node->DstMask == dstmask) )
      if( (node->Type == type) && (node->DstPort == dp) && (node->SrcPort == sp))  {
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



UINT FreeAcl( struct _S5AclNode **node )
{
  struct _S5AclNode *lnode;
  struct _S5AclNode *lnode_prev=NULL;

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


/* ***************************** HASH for AUTHORIZATION CACHE **************************** */
inline UINT S5AuthoCacheHash( char *sa, char *da, UINT dp, char *u )
{
  register int idx;
  register int len;
  register long int hashVal = 0;
  char s[256];

  s[0] = '\0';

  snprintf(s,256 - 1,"%s%s%u%s",sa,da,dp,u);

  len = strlen(s);
  for(idx = 0; idx < len; idx++)
    hashVal = 37*hashVal + s[idx];

  hashVal %= MAXAUTHOCACHELIST;
  if(hashVal < 0)
    hashVal += MAXAUTHOCACHELIST;

  return hashVal;

}

UINT GetAuthoCache( char *sa, char *da, UINT dp, char *u, struct _SS5Facilities *fa, UINT f )
{
  register UINT index;
  struct _S5AuthoCacheNode *node;

    index=S5AuthoCacheHash( sa, da, dp, u );

    if( S5AuthoCacheList[index]!= NULL ) {
      node=S5AuthoCacheList[index];
      do {
        if( STREQ(sa,node->Sa,sizeof(node->Sa)) && STREQ(da,node->Da,sizeof(node->Da)) && (dp == node->Dp) && STREQ(u,node->Us,sizeof(node->Us))) {
          if( node->ttl > time(NULL) ) {
            strncpy(fa->Fixup,node->Fa.Fixup,sizeof(S5AuthoCacheList[index]->Fa.Fixup));
            fa->Bandwidth = node->Fa.Bandwidth;
            node->Flg += f;
            if( node->Flg )
              return OK+100;
            else
              return OK;
          }
          else {
            node->Flg += f;
            return ERR_AUTHOCACHE_EXPIRED;
          }
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}

UINT AddAuthoCache( char *sa,  char *da, UINT dp, char *u, struct _SS5Facilities *fa )
{
  register UINT index;

  struct _S5AuthoCacheNode *node, *prevnode;

  index=S5AuthoCacheHash( sa, da, dp, u );

  if( S5AuthoCacheList[index]== NULL ) {
    if( (S5AuthoCacheList[index]=(struct _S5AuthoCacheNode *)calloc(1,sizeof(struct _S5AuthoCacheNode))) == NULL )
      return ERR;

    strncpy(S5AuthoCacheList[index]->Sa,sa,sizeof(S5AuthoCacheList[index]->Sa));
    strncpy(S5AuthoCacheList[index]->Da,da,sizeof(S5AuthoCacheList[index]->Da));
    S5AuthoCacheList[index]->Dp = dp;
    strncpy(S5AuthoCacheList[index]->Us,u,sizeof(S5AuthoCacheList[index]->Us));
    strncpy(S5AuthoCacheList[index]->Fa.Fixup,fa->Fixup,sizeof(S5AuthoCacheList[index]->Fa.Fixup));
    S5AuthoCacheList[index]->Fa.Bandwidth = fa->Bandwidth;
    S5AuthoCacheList[index]->ttl = (time(NULL) + SS5SocksOpt.AuthoCacheAge);
    S5AuthoCacheList[index]->Flg += 1;
    S5AuthoCacheList[index]->next = NULL;
  }
  else {
    node=S5AuthoCacheList[index];
    do {
      if( STREQ(sa,node->Sa,sizeof(node->Sa)) && STREQ(da,node->Da,sizeof(node->Da)) && (dp == node->Dp) && STREQ(u,node->Us,sizeof(node->Us))) 
        return ERR;

      prevnode=node;
      node=node->next;

    } while( node != NULL );

    if( (node=(struct _S5AuthoCacheNode *)calloc(1,sizeof(struct _S5AuthoCacheNode))) == NULL )
      return ERR;

    node->ttl = (time(NULL) + SS5SocksOpt.AuthoCacheAge);
    strncpy(node->Sa,sa,sizeof(S5AuthoCacheList[index]->Sa));
    strncpy(node->Da,da,sizeof(S5AuthoCacheList[index]->Da));
    node->Dp = dp;
    strncpy(node->Us,u,sizeof(S5AuthoCacheList[index]->Us));
    strncpy(node->Fa.Fixup,fa->Fixup,sizeof(S5AuthoCacheList[index]->Fa.Fixup));
    node->Fa.Bandwidth = fa->Bandwidth;
    node->Flg = +1;
    node->next = NULL;

    prevnode->next=node;
  }
  return OK;
}

UINT UpdateAuthoCache( char *sa, char *da, UINT dp, char *u, UINT f )
{
  register UINT index;
  struct _S5AuthoCacheNode *node;

    index=S5AuthoCacheHash( sa, da, dp, u );

    if( S5AuthoCacheList[index]!= NULL ) {
      node=S5AuthoCacheList[index];
      do {
        if( STREQ(sa,node->Sa,sizeof(node->Sa)) && STREQ(da,node->Da,sizeof(node->Da)) && (dp == node->Dp) && STREQ(u,node->Us,sizeof(node->Us))) {
          if( f == 0 ) 
            node->ttl=(time(NULL) + SS5SocksOpt.AuthoCacheAge);
          else
            node->Flg += f;
          return OK;
        }
        node=node->next;
      } while(node != NULL );
    }

  return ERR;
}



UINT FreeAuthoCache( struct _S5AuthoCacheNode **node )
{
  struct _S5AuthoCacheNode *lnode;
  struct _S5AuthoCacheNode *lnode_prev=NULL;

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

