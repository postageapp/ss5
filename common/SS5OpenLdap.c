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
#include"SS5Mod_log.h"

#ifdef SOLARIS
  #include<lber.h>
  #define LDAP_DEPRECATED
#endif

#include <ldap.h>


UINT DirectoryCheck( char *group, char *user )
{
  register UINT idx1;
  register UINT idx2;

  char ntbdomain[64];
  char ntbuser[64];
  char swap[64];

  UINT count;

  int err = ERR;
  int pos = 0,
      gss = 0;
 
  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid = getpid();
  else
    pid = (UINT)pthread_self();

  /*
   *    Get netbios domain from username
   */
  ntbdomain[0]='\0';
  ntbuser[0]  ='\0';
  swap[0]  ='\0';

  for(idx1 = 0, idx2 = 0; user[idx1] && (idx1 < (sizeof(ntbuser) - 1)); idx1++ ) {
    if( user[idx1] == '\\' || user[idx1] == '@' ) {
      ntbdomain[idx1] = '\0';
      pos = 1; 
      gss++;
      idx1++;
    }

    if( pos == 0 ) {
      ntbdomain[idx1] = user[idx1];
      ntbuser[idx1] = user[idx1];
      ntbuser[idx1 + 1] = '\0';
    }
    else if( pos == 1 ) {
      ntbuser[idx2++] = user[idx1];
      ntbuser[idx2] = '\0';
    }
  }

  /*
   *    If username in the form user@domain.dom ss5 supposes 
   *    a GSS authentication request
   */
  if( gss ) {
    strncpy(swap,ntbuser,sizeof(swap));
    strncpy(ntbuser,ntbdomain,sizeof(ntbuser));
    strncpy(ntbdomain,swap,sizeof(ntbdomain));
  }
  /*
   *    Look for user into all UserStore
   */
  for( count = 0; (err == ERR) && (count < NLdapStore); count++ ) { 
    if( SS5SocksOpt.LdapNetbiosDomain ) {
      /*
       *    Look for only if user netbios domain and directory netbios domain match
       */
      if( STREQ(S5Ldap[count].NtbDomain,"DEF",sizeof("DEF") -1) ) {
        err = DirectoryQuery(pid, group, ntbuser, count);
      }
      else if( STRCASEEQ(S5Ldap[count].NtbDomain,ntbdomain,sizeof(ntbdomain) -1) )
        err = DirectoryQuery(pid, group, ntbuser, count);
    }
    /*
     *    Look for in order of configuration
     */
    else {
      err = DirectoryQuery( pid, group, ntbuser, count);
    }
  }
  return err;
}

UINT DirectoryQuery( pid_t pid, char *group, char *user, int dirid )
{
  register UINT idx1,idx2;

  UINT i,l;

  struct timeval oldapTimeout;

  char searchFilter[128]="\0";
  char baseDn[128]      ="\0";
  char baseTmp[128]     ="\0";
  char ldap_uri[128]    ="\0";

  char *attrsList[] = {"dn", NULL };

  LDAP	*ld      = NULL;

  LDAPMessage *result;

  int rc;
  int protocolVersion = LDAP_VERSION3;

  char logString[256]="\0";

  /*
   *    Set timeout for ldap query
   */
  oldapTimeout.tv_sec  = SS5SocksOpt.LdapTimeout;
  oldapTimeout.tv_usec = 0;

  /*
   *    build "searchFilter" for ldap query
   */
  if( LDAPBASE() ) {
    strncpy(searchFilter,S5Ldap[dirid].Filter,sizeof(searchFilter));
    STRSCAT(searchFilter,"=");
    STRSCAT(searchFilter,user);
  }
  else if( LDAPFILTER() ) {
    strncpy(searchFilter,"(&(",sizeof(searchFilter));
    STRSCAT(searchFilter,S5Ldap[dirid].Filter);
    STRSCAT(searchFilter,"=");
    STRSCAT(searchFilter,user);
    STRSCAT(searchFilter,")(");
    STRSCAT(searchFilter,S5Ldap[dirid].Attribute);
    STRSCAT(searchFilter,"=");
    STRSCAT(searchFilter,group);
    STRSCAT(searchFilter,"))");
  }
  /*
   *    build "base" for ldap query
   */
  for(idx1 = 0; (baseDn[idx1] = S5Ldap[dirid].Base[idx1]) != '%' && idx1 < strlen(S5Ldap[dirid].Base); idx1++);
  baseDn[idx1] = '\0';
  if( (idx1++) < strlen(S5Ldap[dirid].Base) ) {
    for(idx2 = 0; (baseTmp[idx2] = S5Ldap[dirid].Base[idx1]) != '\0' && idx1 < strlen(S5Ldap[dirid].Base); idx2++, idx1++);
    baseTmp[idx2] = '\0';

    STRSCAT(baseDn,group);
    STRSCAT(baseDn,baseTmp);
  }

  /*
   *    Initialize ldap environment
   */
#ifdef LDAP_DEPRECATED
  ld = (LDAP *)ldap_init( S5Ldap[dirid].IP, atoi(S5Ldap[dirid].Port) );
  if ( ld == NULL ) {
    ERRNO(pid)

    return ERR;
  }
#else
  sprintf(ldap_uri,"ldap://%s:%d/",S5Ldap[dirid].IP,atoi(S5Ldap[dirid].Port));
  if( ldap_initialize( &ld, ldap_uri) != LDAP_SUCCESS ) {
    ERRNO(pid)

    return ERR;
  }
#endif

  ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &protocolVersion ); 
  ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF ); 
  /*
   *    Try to bind into directory
   */
  if (( rc = ldap_bind_s( ld, S5Ldap[dirid].Dn, S5Ldap[dirid].Pass, LDAP_AUTH_SIMPLE )) != LDAP_SUCCESS ) {
    ERRNOLDAP(pid,rc)

    ldap_unbind( ld );
    return ERR;
  }
  /*
   *    Search for username into directory
   */
  if (( rc = ldap_search_st( ld, baseDn, LDAP_SCOPE_SUBTREE, searchFilter, attrsList, 0, &oldapTimeout, &result )) != LDAP_SUCCESS ) { 
    ERRNOLDAP(pid,rc)

    ldap_msgfree( result );
    ldap_unbind( ld );

    return ERR;
  }
  else {
    /*
     *    Count entries, if zero NOT FOUND!
     */
    if( ldap_count_entries( ld, result ) ) {
      ldap_msgfree( result );
      ldap_unbind( ld );

      return OK;
    }
  }

  ldap_msgfree( result );
  ldap_unbind( ld );

  return ERR;
}

