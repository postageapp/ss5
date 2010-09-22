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
#include"SS5Server.h"
#include"SS5Mod_balance.h"
#include"SS5Mod_authentication.h"
#include"SS5Mod_authorization.h"
#include"SS5Utils.h"
#include"SS5Radius.h"
#ifdef SS5_USE_MYSQL
  #include"SS5MySql.h"
#endif

void S5SetStatic( void )
{
  /* 
   *    Allocate memory for server data
   */
  S5AuthCmd=(struct _S5AuthCmd *)calloc( 1, sizeof( struct _S5AuthCmd ));

  /*
   *    Set socks server default static values 
   *    Changes require socks restart
   */
  SS5SocksOpt.IsThreaded       = ERR;
  SS5SocksOpt.Mute             = ERR;
  SS5SocksOpt.PreforkProcesses = 1;
  SS5SocksOpt.PropagateKey     = 0;
  SS5SocksOpt.Role             = ALONE;
  S5Radius.AuthPort            = RADIUS_AUTH_PORT;
  S5Radius.AcctPort            = RADIUS_ACCT_PORT;

  strncpy(S5ConfigFile,SS5_CONFIG_FILE,sizeof(S5ConfigFile));
  strncpy(S5PeersFile,SS5_PEERS_FILE,sizeof(S5PeersFile));
  strncpy(S5PasswordFile,SS5_PASSWORD_FILE,sizeof(S5PasswordFile));
  strncpy(S5LibPath,SS5_LIB_PATH,sizeof(S5LibPath));
  strncpy(S5ProfilePath,SS5_PROFILE_PATH,sizeof(S5ProfilePath));
  strncpy(S5TracePath,SS5_TRACE_PATH,sizeof(S5TracePath));
  strncpy(S5LoggingFile,SS5_LOG_FILE,sizeof(S5LoggingFile));
  strncpy(S5PidFileName,SS5_PID_FILE,sizeof(S5PidFileName));
}

void S5SetDynamic( void )
{
  /*
   *    Set socks server default dinamic values 
   *    Changes require socks reload only
   */
  SS5SocksOpt.SessionIdleTimeout = 1800;
  SS5SocksOpt.AcceptTimeout      = 10;
  SS5SocksOpt.LdapTimeout        = 30;
  SS5SocksOpt.LdapNetbiosDomain  = ERR;
  SS5SocksOpt.AuthCacheAge       = 0;
  SS5SocksOpt.AuthoCacheAge      = 0;
  SS5SocksOpt.PreforkProcessLife = 256;
  SS5SocksOpt.StickyAge          = STICKY_AGE;
  SS5SocksOpt.Sticky             = ERR;
  SS5SocksOpt.Verbose            = ERR;
  SS5SocksOpt.Debug              = ERR;
  SS5SocksOpt.DnsOrder           = ERR;
  SS5SocksOpt.IsBalance          = ERR;
  SS5SocksOpt.IsDump             = ERR;
  SS5SocksOpt.IsConsole          = ERR;
  SS5SocksOpt.IsSrvmgr           = ERR;
  SS5SocksOpt.IsUpstream         = ERR;
  SS5SocksOpt.IsRoute            = ERR;
  SS5SocksOpt.IsBandwidth        = ERR;
  SS5SocksOpt.IsGlobalBandwidth  = ERR;
  SS5SocksOpt.Profiling          = FILE_PROFILING;
  SS5SocksOpt.LdapCriteria       = LDAP_BASE;
  SS5SocksOpt.Authentication     = FILE_AUTHENTICATION;
  SS5SocksOpt.SyslogFa		 = LOG_LOCAL6;
  SS5SocksOpt.SyslogLe           = LOG_ERR;
  SS5SocksOpt.SupaKey[0]         = '\0';
  SS5SocksOpt.GssPrincipal[0]    = '\0';
  SS5SocksOpt.ICacheServer[0]    = '\0';
  SS5SocksOpt.RadIntUpdInterval       =   60;
  SS5SocksOpt.RadSessionIdleTimeout   =    0;
  SS5SocksOpt.RadSessionTimeout       =    0;
  SS5SocksOpt.RadInterimTimeout       = 9999;

#ifdef SS5_USE_MYSQL
  strncpy(S5Mysql.SqlString,SQLSTRING,sizeof(SQLSTRING));
#endif

  NLdapStore = 0;
  NPeers     = 0;
}

inline UINT S5ChildClose(int exitCode, UINT childSocket, struct _SS5ClientInfo *ci)
{
#ifdef SS5_USE_GSSAPI
  OM_uint32 tmp;
#endif

  if( childSocket > 2)
    close( childSocket);

#ifdef SS5_USE_GSSAPI
  if( ci != NULL && (ci->GssContext != GSS_C_NO_CONTEXT) )
      gss_delete_sec_context(&tmp, &ci->GssContext, NULL);
#endif

  fflush(S5LogFile);

  if( NOTTHREADED() ) {
    if( exitCode )
      exit(0);
  }
  return OK;
}


UINT S5ServerClose(int exitCode)
{
  /* 
   *    Free father resources and close it 
   */
  close(S5SocksSocket);

  if( exitCode ) {
    if( VERBOSE() )
      SS5Modules.mod_logging.Logging("[VERB] SS5 exiting.");

    if (unlink(S5PidFileName)!=0) {
      fprintf(stderr,"Can't unlink pid file %s\n",S5PidFileName);
    }

    exit(0);
  }
  return OK;
}

UINT S5UIDSet( char *username )
{
  struct passwd *pwd;
  
  char logString[128];

  /* 
   *    Look for user/group to run ss5
   */
  if( (pwd=getpwnam(username)) == NULL ) {
    ERRNO(0)
    return ERR;
  }

  if( setgid(pwd->pw_gid) < 0 )
    return ERR;

  if (initgroups(username, pwd->pw_gid) < 0)
    return ERR;

  if( setuid(pwd->pw_uid) < 0 )
    return ERR;

  return OK;
}

UINT S5MakeDaemon( void )
{
  pid_t pid;

  pid=fork();

  /*    If father then exit    */
  if( pid )
    exit(0);
  /*    If child then continue and become process group leader    */
  else if( pid != -1 )
    setsid(); 	
  else
    return ERR;

  pid=fork();  	
  /*    No terminal association    */
  if( pid ) 
    exit(0); 
  else if( pid != -1 ) {
    chdir("/");    umask(0);	
  }
  else
    return ERR;

  return OK;
}

UINT S5ServerMake( char *addr, UINT port )
{
  int reuseAddrFlag = 1;

  char logString[128];

  if ((S5SocksSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    ERRNO(0)     
    return ERR;
  }

  /*
   *    Bind socks server on ANY or a specified address (set by comman line)
   */
  memset((char *)&S5SocksSsin, 0, sizeof(struct sockaddr_in));

  S5SocksSsin.sin_family = AF_INET;

  if( port )
    S5SocksSsin.sin_port = htons(port);
  else
    S5SocksSsin.sin_port = htons(SOCKS5_PORT);

  if( STREQ(addr,"0.0.0.0\0",sizeof("0.0.0.0\0") - 1) )
    S5SocksSsin.sin_addr.s_addr = htonl(INADDR_ANY);
  else
    S5SocksSsin.sin_addr.s_addr = inet_addr(addr);

  setsockopt(S5SocksSocket, SOL_SOCKET, SO_REUSEADDR, &reuseAddrFlag, sizeof(int));

  if (bind(S5SocksSocket, (struct sockaddr *)&S5SocksSsin, sizeof(struct sockaddr_in)) == -1) {
    ERRNO(0)
    return ERR;
  }

  /*
   *    Listen: maximum queue length of pending connections is 5
   */
  if (listen(S5SocksSocket, 6) == -1) {
    ERRNO(0)
    return ERR;
  }
  return OK;
}


UINT S5ServerAccept( struct sockaddr_in *clientSsin, int *clientSocket )
{
  socklen_t len;

  char logString[128];

  len = sizeof (struct sockaddr_in);
  if( ((*clientSocket) = (int)accept(S5SocksSocket, (struct sockaddr *)clientSsin, &len)) == -1 ) {
    ERRNO(0)   
    return ERR;
  }
  return OK;
}

UINT S5GetClientInfo(struct _SS5ClientInfo *ci, UINT clientSocket, pid_t pid)
{
  UINT len;

  struct sockaddr_in sockAddr;
  struct in_addr in;

  char logString[128];

  /*
   *    Get socket name, ip address and port
   */
  ci->Socket=clientSocket;

  len=sizeof(struct sockaddr);
  if( getpeername(clientSocket,(struct sockaddr *)&sockAddr,&len) == -1 ) {
    ERRNO(pid);
    return ERR;
  }

  in.s_addr=sockAddr.sin_addr.s_addr;
  strncpy(ci->SrcAddr,(char *)inet_ntoa(in),sizeof(ci->SrcAddr));
  ci->SrcPort=ntohs(sockAddr.sin_port);

  return OK;
}

