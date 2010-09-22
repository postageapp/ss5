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
#include"SS5Mod_socks5.h"
#include"SS5Mod_balance.h"
#include"SS5Mod_dump.h"
#include"SS5Mod_authentication.h"
#include"SS5Mod_bandwidth.h"
#include"SS5Mod_authorization.h"
#include"SS5Radius.h"
#include"SS5OpenLdap.h"
#ifdef SS5_USE_MYSQL
  #include"SS5MySql.h"
#endif
#include"SS5Utils.h"
#include"SS5Thread.h"
#include"SS5Server.h"
#include <sys/socket.h>
#include <netinet/in.h>



UINT S5LoadConfig( UINT loadMode )
{
  char logString[256];

  if( loadMode != PARSE_CONFIG ) {
    SS5Modules.mod_logging.Logging("[INFO] -------------------------------------------------------------------------------------------------------");
    if( loadMode == RELOAD_CONFIG ) {
      snprintf(logString,256 - 1,"[INFO] %s reloading",SS5_VERSION);
      LOGUPDATE()
    }
    else {
      snprintf(logString,256 - 1,"[INFO] %s starting",SS5_VERSION);
      LOGUPDATE()
    }

    snprintf(logString,256 - 1,"[INFO] %s",SS5_COPYRIGHT);
    LOGUPDATE()
  }

  /*
   * Allocate memory space for data
   */
  if( S5AllocConfData() == ERR ) {
    SS5Modules.mod_logging.Logging("[ERRO] Error allocating new configuration.");
    return ERR;
  }

  /*
   * Initialize server dynamic data to default values
   */
  if( loadMode != PARSE_CONFIG ) 
    SS5Modules.mod_logging.Logging("[INFO] Setting dynamic configuration.");

  S5SetDynamic();

  /*
   * Free config data
   */
  if( loadMode != PARSE_CONFIG ) 
    SS5Modules.mod_logging.Logging("[INFO] Cleaning old configuration.");

  S5FreeConfData();

  /*
   * Parse and load configuration data
   */
  if( loadMode != PARSE_CONFIG ) 
    SS5Modules.mod_logging.Logging("[INFO] Loading and validating new configuration.");

  /*
   * TO DO: free _tmp_ data
   */
  if( S5LoadConfData(loadMode) == ERR ) {
    SS5Modules.mod_logging.Logging("[ERRO] Configuration not switched.");
    return ERR;
  }
  /*
   * Switch config data
   */
  if( loadMode != PARSE_CONFIG ) 
    SS5Modules.mod_logging.Logging("[INFO] Switching to new configuration.");

  S5SwitchConfData();

  /*
   * Load peers if defined in ss5.ha file
   */
  if( S5LoadPeers() && NPeers ) 
    SS5SocksOpt.Role = MASTER;

  switch( SS5SocksOpt.Role ) {
    case MASTER:
      snprintf(logString,256 - 1,"[VERB] Role is MASTER.");
    break;
    case SLAVE:
      snprintf(logString,256 - 1,"[VERB] Role is SLAVE.");
    break;
    case ALONE:
      snprintf(logString,256 - 1,"[VERB] Role is ALONE.");
    break;
  }
  LOGUPDATE()

  /*
   * If MASTER, propagate configuration to peers
   */
  if( SS5SocksOpt.Role == MASTER )
    S5PropagateConfig();

  return OK;
}

UINT S5LoadPeers( void )
{
  char logString[256];
  char confString[256];

  /*
   * Open ss5.ha file
   */
  if( (S5PeerFile = fopen(S5PeersFile,"r")) == NULL ) {
    fprintf (stderr, "[WARN] %s not found.\n", S5PeersFile);
    return ERR;
  }

  while( fscanf(S5PeerFile,"%255s",confString)!=EOF ) {
    if( confString[0] == '#' ) {
        while( fgetc(S5PeerFile) != '\n' );
    }
    else if( STREQ(confString,"peer\0",sizeof("peer\0") - 1) ) {

      if( fscanf(S5PeerFile,"%32s\n",SS5Peer[NPeers].IP) < 1 ) {
        ERRNO(0)
        fclose(S5PeerFile);
        return ERR;
      }
      if( SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Peer (ip):        %64s.",SS5Peer[NPeers].IP);
        LOGUPDATE()
      }
      if( NPeers < MAXPEERS )
        NPeers ++;
      else {
         snprintf(logString,256 - 1,"[ERRO] Maximum number of peer lines reached: %d.",MAXPEERS);
         LOGUPDATE()

        fclose(S5PeerFile);
        return ERR;
      }
    }
  }
  
  fclose(S5PeerFile);

  return OK;
}

UINT S5ReceiveConfig( struct _SS5ClientInfo *ci, struct _SS5Socks5Data *sd )
{
  char *buf;
  char logString[256];
  char repMsg[16]; 
  char repChunk[REPCHUNK];

  ULINT repSize;
  ULINT repKey;

  ULINT index;

  FILE *ou;

  /*
   * Read replica header
   */
  sscanf(sd->MethodRequest,"%13s:%lu:%lu\n",repMsg,&repSize,&repKey);

  if( STREQ(repMsg,"PROPAGATE_KEY\0",sizeof("PROPAGATE_KEY\0") - 1) ) {
    if( VERBOSE() )  {
      snprintf(logString,256 - 1,"[VERB] PROPAGATE_KEY command received.");
      LOGUPDATE()
    }
    
    if( (buf = calloc(repSize + REPCHUNK, sizeof(char))) == NULL )
      return ERR;

    for(index = 0; index < repSize ; index +=REPCHUNK ) {
      if( recv(ci->Socket,repChunk,REPCHUNK,MSG_WAITALL) < 0 ) {
        ERRNO(0)
        free(buf);

        return ERR;
      }
      S5Memcpy(buf,repChunk,index,0);
    }


  }
  else
    return ERR;

  if( SS5SocksOpt.PropagateKey == repKey) {
    if( VERBOSE() )  {
      snprintf(logString,256 - 1,"[VERB] PROPAGATE_KEY key match.");
      LOGUPDATE()
    }
    /*
     * Open local config file for update
     */
    if( (ou = fopen(S5ConfigFile,"w")) == NULL ) {
      ERRNO(0)
      free(buf);

      return ERR;
    }
  
    if( fwrite(buf, sizeof(char), repSize, ou) == 0 ) {
      ERRNO(0)
      free( buf ); 
      fclose(ou);
  
      return ERR;
    }
    free(buf);
    fclose(ou);

    return OK;
  }
  else {
    if( VERBOSE() )  {
      snprintf(logString,256 - 1,"[VERB] PROPAGATE_KEY key MISmatch.");
      LOGUPDATE()
    }
  }

  free(buf);

  return ERR;
}

UINT S5PropagateConfig( void )
{
  char *buf;
  char logString[256];
  char repHeader[512];
  char repChunk[REPCHUNK];

  long int index;
  UINT count;

  int peer_socket;

  struct  stat fs;

  struct sockaddr_in peer_ssin;

  FILE *in;

  memset(repHeader,0, sizeof(repHeader));
  /*
   * Get information about local config file size
   */
  if( stat(S5ConfigFile, (struct stat *)&fs) == -1 ) {
    ERRNO(0)
    return ERR;
  }

  snprintf(repHeader,256 - 1,"PROPAGATE_KEY:%lu:%lu",(ULINT)fs.st_size,(ULINT)SS5SocksOpt.PropagateKey);
  /*
   * Open local config file
   */
  if( (in = fopen(S5ConfigFile,"r")) == NULL ) {
    ERRNO(0)
    return ERR;
  }

  /*
   * Alloc buffer before reading local config file
   */
  if( (buf = calloc(fs.st_size + REPCHUNK, sizeof(char))) == NULL ) {
    ERRNO(0)
    fclose(in);

    return ERR;
  }

  if( fread(buf, sizeof(char), fs.st_size, in) == 0 ) {
    ERRNO(0)
    free( buf ); fclose(in);

    return ERR;
  }
  
  fclose(in);

  /*
   * For each peer defined, propagate config file to the network
   */

  memset((char *)&peer_ssin, 0, sizeof(struct sockaddr_in));
  peer_ssin.sin_family = AF_INET;
  peer_ssin.sin_port = htons(SOCKS5_PORT);

  for(count = 0; count <NPeers; count++ ) {
    peer_ssin.sin_addr.s_addr = inet_addr(SS5Peer[count].IP);

    if ((peer_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      ERRNO(0)     
      free(buf);
      return ERR;
    }
    if( VERBOSE() )  {
      snprintf(logString,256 - 1,"[VERB] Propagating config to peer: %s.",SS5Peer[count].IP);
      LOGUPDATE()
    }

    /*
     * Connect to peer
     */
    if( connect(peer_socket,(struct sockaddr *)&peer_ssin,sizeof(struct sockaddr_in)) == -1 ) {
      ERRNO(0)
      close(peer_socket);
      fprintf(stdout,"\n[WARN] Error propagating config to peer: %s.\n",SS5Peer[count].IP);
    }
    else { 
      /*
       * Send replication header to slave
       */
      if( send(peer_socket,repHeader,sizeof(repHeader), SS5_SEND_OPT) == -1) {
        ERRNO(0)
        close(peer_socket);
      }
      /*
       * Send configuration file to slave
       */
      for(index = 0; index < fs.st_size ; index +=REPCHUNK ) {

        S5Memcpy(repChunk,buf,0,index);
        if( send(peer_socket,repChunk,REPCHUNK, SS5_SEND_OPT) == -1) {
          ERRNO(0)
          close(peer_socket);
        }
      }
      close(peer_socket);
    }
  }
  free(buf);

  return OK;
}


void S5Memcpy(char *dst,char *src,ULINT dsti,ULINT srci)
{
  register ULINT j;

  for(j=0;j<REPCHUNK;j++)
    dst[dsti + j]=src[srci + j];
}


UINT S5LoadConfData( UINT m )
{
  FILE *grpf;

  char logString[256];
  char confString[256];
  char optionString[256];

  struct in_addr in;

  struct _SS5Facilities fa;

  struct _SS5ParseConfFile pcf;

  UINT method,
               srcMask,
               dstMask,
               socksver,
               sdr,i,l;

  /* 
   * Open socks server configuration file 
   */
  if( (S5ConfFile = fopen(S5ConfigFile,"r")) == NULL ) {
    ERRNO(0)
    return ERR;
  }

  /* 
   * Load socks server configuration information 
   */
  while( fscanf(S5ConfFile,"%255s",confString)!=EOF ) {
    /*
     * Skip commnents
     */
    if( confString[0] == '#' ) {
        while( fgetc(S5ConfFile) != '\n' );
    }
    /*
     * Parse <permit> directive
     */
    else if( STREQ(confString,"permit\0",sizeof("permit\0") - 1) || STREQ(confString,"deny\0",sizeof("deny\0") - 1) ) {

      if( _tmp_NAclList < MAXACLLIST ) {
        if( fscanf(S5ConfFile,"%1s %64s %16s %64s %16s %16s %256s %16s %10s\n",pcf.socksMeth,pcf.srcAddr,pcf.srcPort,pcf.dstAddr,pcf.dstPort,pcf.fixup,pcf.group,pcf.bandwidth,pcf.expDate) < 9 ) {
          ERRNO(0)
          return ERR;
        }

        switch(pcf.socksMeth[0]) {
          case '-':    method=NOAUTH;    break;
          case 'u':    method=USRPWD;    break;
          case 'n':    method=FAKEPWD;   break;
          case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
          case 'k':    method=GSSAPI;      break;
#endif
          default:     SS5Modules.mod_logging.Logging("[ERRO] Method unknown in permit line.");    return ERR;    break;
        }

        if( pcf.bandwidth[0] == '-' )
          strncpy(pcf.bandwidth,"0\0",2);

        strncpy(fa.Fixup,pcf.fixup,sizeof(fa.Fixup));
        strncpy(fa.Group,pcf.group,sizeof(fa.Group));
        fa.Bandwidth=atoi(pcf.bandwidth);
        strncpy(fa.ExpDate,pcf.expDate,sizeof(fa.ExpDate));

        srcMask=S5GetNetmask(pcf.srcAddr);
        dstMask=S5GetNetmask(pcf.dstAddr);

        if( (pcf.srcAddr[0] > 64) && (pcf.dstAddr[0] >64) ) {
          SS5Modules.mod_authorization.AddAcl(OFFLINE,STREQ(confString,"permit",sizeof("permit") - 1)?PERMIT:DENY,S5StrHash(pcf.srcAddr),pcf.srcAddr,
                                              S5GetRange(pcf.srcPort),
          S5StrHash(pcf.dstAddr),pcf.dstAddr,S5GetRange(pcf.dstPort),32-srcMask,32-dstMask,method,&fa);
        }
        else if( pcf.dstAddr[0] >64 ) {
          SS5Modules.mod_authorization.AddAcl(OFFLINE,STREQ(confString,"permit",sizeof("permit") - 1)?PERMIT:DENY,inet_network(pcf.srcAddr),"-",
          S5GetRange(pcf.srcPort), S5StrHash(pcf.dstAddr),pcf.dstAddr,S5GetRange(pcf.dstPort),32-srcMask,32-dstMask,method,&fa);
        }
        else if ( pcf.srcAddr[0] > 64 ) {
          SS5Modules.mod_authorization.AddAcl(OFFLINE,STREQ(confString,"permit",sizeof("permit") - 1)?PERMIT:DENY,S5StrHash(pcf.srcAddr),pcf.srcAddr,S5GetRange(pcf.srcPort),
          inet_network(pcf.dstAddr),"-",S5GetRange(pcf.dstPort),32-srcMask,32-dstMask,method,&fa);
        }
        else {
          SS5Modules.mod_authorization.AddAcl(OFFLINE,STREQ(confString,"permit",sizeof("permit") - 1)?PERMIT:DENY,inet_network(pcf.srcAddr),"-",
          S5GetRange(pcf.srcPort),inet_network(pcf.dstAddr),"-",S5GetRange(pcf.dstPort),32-srcMask,32-dstMask,method,&fa);
        }

        _tmp_NAclList++;
      }
      else {
        if( m != PARSE_CONFIG )  {
          snprintf(logString,256 - 1,"[ERRO] Maximum number of permit lines reached: %d.",MAXACLLIST);
          LOGUPDATE()
        }
        return ERR;
      }
    }
    /*
     * Parse <auth> directive
     */
    else if( STREQ(confString,"auth\0",sizeof("auth\0") - 1) ) {

      if( _tmp_NMethodList < MAXACLLIST ) {
        if( fscanf(S5ConfFile,"%20s %16s %1s\n",pcf.srcAddr,pcf.srcPort, pcf.socksMeth) < 3 ) {
          ERRNO(0)
          return ERR;
        }

        switch(pcf.socksMeth[0]) {
          case '-':    method=NOAUTH;      break;
          case 'u':    method=USRPWD;      break;
          case 'n':    method=FAKEPWD;     break;
          case 's':    method=S_USER_PWD;  break;
#ifdef SS5_USE_GSSAPI
          case 'k':    method=GSSAPI;      break;
#endif
          default:     SS5Modules.mod_logging.Logging("[ERRO] Method unknown in auth line.");    return ERR;    break;
        }

        srcMask=S5GetNetmask(pcf.srcAddr);

        if( SS5Modules.mod_socks5.AddMethod(OFFLINE,inet_network(pcf.srcAddr),S5GetRange(pcf.srcPort),method,32-srcMask) == ERR ) {
          snprintf(logString,256 - 1,"[WARN] Duplicate auth lines in config file.");
          LOGUPDATE()
        }
        else
          _tmp_NMethodList++;
      }
      else {
        if( m != PARSE_CONFIG )  {
          snprintf(logString,256 - 1,"[ERRO] Maximum number of auth lines reached: %d.",MAXACLLIST);
          LOGUPDATE()
        }
        return ERR;
      }
    }
    /*
     * Parse <bandwidth> directive
     */
    else if( STREQ(confString,"bandwidth\0",sizeof("bandwidth\0") - 1) ) {
      if( _tmp_NBandwidthList < MAXBANDLIST ) {
        if( fscanf(S5ConfFile,"%128s %6s %16s\n",pcf.group,pcf.lCon,pcf.bandwidth) < 3 ) {
          ERRNO(0)
          return ERR;
        }

        if( pcf.bandwidth[0] == '-' )
          strncpy(pcf.bandwidth,"0\0",2);

        if( pcf.lCon[0] == '-' )
          strncpy(pcf.lCon,"0\0",2);

        if( pcf.group[0] != '-' ) {
         /*
          * Explodes bandwidth group definition into singles bandwidth directives
          */
          strncpy(pcf.groupPath,S5ProfilePath,sizeof(pcf.groupPath));
          STRSCAT(pcf.groupPath,"/");
          STRSCAT(pcf.groupPath,pcf.group);
          
          if( (grpf = fopen(pcf.groupPath,"r")) == NULL ) {
            ERRNO(0)
            return ERR;
          // TODO: _tmp_NBandwidthList =0
          }
          while( fscanf(grpf,"%64s",pcf.user) != EOF ) {
            if( pcf.user[0] != '#' ) {
              if( _tmp_NBandwidthList < MAXBANDLIST ) {
                SS5Modules.mod_bandwidth.AddBandTable( OFFLINE, pcf.user, atoi(pcf.lCon), atol(pcf.bandwidth) );
                _tmp_NBandwidthList++;
              }
              else {
                if( m != PARSE_CONFIG )  {
                  snprintf(logString,256 - 1,"[ERRO] Maximum number of bandwidth lines reached: %d.",MAXBANDLIST);
                  LOGUPDATE()
  
                  fclose(grpf);
                }
                return ERR;
              }
            }
          }
          fclose(grpf);
        }
        /* Set bandwith and connection limit for all users */
        else {
	  SS5SocksOpt.IsGlobalBandwidth = OK;
          S5GlobalBandwidth.BandW=atoi(pcf.bandwidth);
          S5GlobalBandwidth.LCon=atoi(pcf.lCon);
        }
      }
      else {
        if( m != PARSE_CONFIG )  {
          snprintf(logString,256 - 1,"[ERRO] Maximum number of bandwidth lines reached: %d.",MAXBANDLIST);
          LOGUPDATE()
        }
        return ERR;
      }
    }
    /*
     * Parse <proxy> directive
     */
    else if( STREQ(confString,"proxy\0",sizeof("proxy\0") - 1) || STREQ(confString,"noproxy\0",sizeof("noproxy\0") - 1) ) {

      if( _tmp_NProxyList < MAXPROXYLIST ) {
        if( fscanf(S5ConfFile,"%20s %16s %16s %6s %1s\n",pcf.dstAddr,pcf.dstPort,pcf.pxyAddr,pcf.pxyPort,pcf.upSocksV) < 5 ) {
          ERRNO(0)
          return ERR;
        }
        switch(pcf.upSocksV[0]) {
          case '-':    socksver=SOCKS5_VERSION;    break;
          case '5':    socksver=SOCKS5_VERSION;    break;
          case '4':    socksver=SOCKS4_VERSION;    break;
          default:     SS5Modules.mod_logging.Logging("[ERRO] Version unknown in proxy line.");    return ERR;    break;
        }

        dstMask=S5GetNetmask(pcf.dstAddr);

        in.s_addr=inet_addr(pcf.pxyAddr);

        if( pcf.dstAddr[0] >64 ) {
          SS5Modules.mod_socks5.AddProxy(OFFLINE,STREQ(confString,"proxy",sizeof("proxy") - 1)?PROXY:NOPROXY,S5StrHash(pcf.dstAddr),S5GetRange(pcf.dstPort),in.s_addr,atoi(pcf.pxyPort),32-dstMask,socksver);
        }
        else
          SS5Modules.mod_socks5.AddProxy(OFFLINE,STREQ(confString,"proxy",sizeof("proxy") - 1)?PROXY:NOPROXY,inet_network(pcf.dstAddr),S5GetRange(pcf.dstPort),in.s_addr,atoi(pcf.pxyPort),32-dstMask,socksver);

        _tmp_NProxyList++;

	SS5SocksOpt.IsUpstream = OK;
      }
      else {
        if( m != PARSE_CONFIG )  {
          snprintf(logString,256 - 1,"[ERRO] Maximum number of proxy lines reached: %d.",MAXPROXYLIST);
          LOGUPDATE()
        }
        return ERR;
      }
    }
    /*
     * Parse <dump> directive
     */
    else if( STREQ(confString,"dump\0",sizeof("dump\0") - 1) ) {

      if( SS5Modules.mod_dump_loaded ) {

        if( _tmp_NDumpList < MAXDUMPLIST ) {
          if( fscanf(S5ConfFile,"%64s %16s %1s\n",pcf.dstAddr,pcf.dstPort,pcf.dumpDir) < 3 ) {
            ERRNO(0)
            return ERR;
          }
  
          switch(pcf.dumpDir[0]) {
            case 'r':     sdr=0;     break;
            case 't':     sdr=1;     break;
            case 'b':     sdr=2;     break;
            default:      sdr=0;     break;
          }

          dstMask=S5GetNetmask(pcf.dstAddr);
  
          if( pcf.dstAddr[0] >64 ) {
            SS5Modules.mod_dump.AddDump(OFFLINE,S5StrHash(pcf.dstAddr),S5GetRange(pcf.dstPort),sdr,32-dstMask);
          }
          else
            SS5Modules.mod_dump.AddDump(OFFLINE,inet_network(pcf.dstAddr),S5GetRange(pcf.dstPort),sdr,32-dstMask);
  
          _tmp_NDumpList++;
 
          SS5SocksOpt.IsDump = OK;
        }
        else {
          if( m != PARSE_CONFIG )  {
            snprintf(logString,256 - 1,"[ERRO] Maximum number of dump lines reached: %d.",MAXDUMPLIST);
            LOGUPDATE()
          }
          return ERR;
        }
      }
      else {
        SS5Modules.mod_logging.Logging("[ERRO] Module dump not loaded. You can not use dump line.");
        return ERR;
      }
    }
    /*
     * Parse <generic external authentication program> directive
     */
    else if( STREQ(confString,"external_auth_program\0",sizeof("external_auth_program\0") - 1) ) {
      if( fscanf(S5ConfFile,"%128s\n",S5AuthCmd->ProgName) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      SS5SocksOpt.Authentication=EAP_AUTHENTICATION;

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose )  {
        snprintf(logString,256 - 1,"[VERB] Eap: %s.",S5AuthCmd->ProgName);
        LOGUPDATE()
      }
    }
    /*
     * Parse <virtual> directive
     */
    else if( STREQ(confString,"virtual\0",sizeof("virtual\0") - 1) ) {
      if( SS5Modules.mod_balancing_loaded ) {
        if( NOTTHREADED() ) {
          if( m != PARSE_CONFIG )
            SS5Modules.mod_logging.Logging("[ERRO] SLB feature only available if ss5 is running in thread mode (use -t option).");
  
          return ERR;
        }
  
        if( _tmp_NReal < MAX_ENTRY_REAL ) {
          if( fscanf(S5ConfFile,"%5s %15s\n",pcf.vid,pcf.real) < 2 ) {
            ERRNO(0)
            return ERR;
          }
  
          SS5Modules.mod_balancing.AddVip(pcf.real,atoi(pcf.vid),_tmp_NReal);
          _tmp_NReal++;
  
          if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
            snprintf(logString,256 - 1,"[VERB] Virtual: %16s %5d.",pcf.real,atoi(pcf.vid));
            LOGUPDATE()
          }
  
          SS5SocksOpt.IsBalance = OK;
        }
        else {
          if( m != PARSE_CONFIG ) {
            snprintf(logString,256 - 1,"[ERRO] Maximum number of virtual lines reached: %d.",MAX_ENTRY_REAL);
            LOGUPDATE()
          }
  
          return ERR;
        }
      }
      else {
        SS5Modules.mod_logging.Logging("[ERRO] Module balance not loaded. You can not use virtual line.");
        return ERR;
      }
    }
    /*
     * Parse the following directory information directives:
     *
     * <radius_ip>
     * <radius_bck_ip>
     * <radius_auth_port>
     * <radius_acct_port>
     * <radius_secret>
     */
    else if( STREQ(confString,"radius_ip\0",sizeof("radius_ip\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Radius.IP) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Radius (ip):        %16s.",S5Radius.IP);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"radius_bck_ip\0",sizeof("radius_bck_ip\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Radius.IPBck) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Radius (secondary ip):        %16s.",S5Radius.IPBck);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"radius_auth_port\0",sizeof("radius_auth_port\0") - 1) ) {
      if( fscanf(S5ConfFile,"%6u\n",&S5Radius.AuthPort) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Radius auth port:   %16d.",S5Radius.AuthPort);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"radius_acct_port\0",sizeof("radius_acct_port\0") - 1) ) {
      if( fscanf(S5ConfFile,"%6u\n",&S5Radius.AcctPort) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Radius acct port:   %16d.",S5Radius.AcctPort);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"radius_secret\0",sizeof("radius_secret\0") - 1) ) {
      if( fscanf(S5ConfFile,"%32s\n",S5Radius.Secret) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Radius secret:      %16s.",S5Radius.Secret);
        LOGUPDATE()
      }
    }
#ifdef SS5_USE_MYSQL
    /*
     * Parse the following MYSQL information directives:
     *
     * <mysql_profile_ip>
     * <mysql_profile_user>
     * <mysql_profile_pass>
     */
    else if( STREQ(confString,"mysql_profile_ip\0",sizeof("mysql_profile_ip\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Mysql.IP) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      SS5SocksOpt.Profiling=MYSQL_PROFILING;

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Mysql server (ip):          %64s.",S5Mysql.IP);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"mysql_profile_db\0",sizeof("mysql_profile_db\0") - 1) ) {
      if( fscanf(S5ConfFile,"%64s\n",S5Mysql.DB) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Mysql server (db):          %64s.",S5Mysql.DB);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"mysql_profile_user\0",sizeof("mysql_profile_user\0") - 1) ) {
      if( fscanf(S5ConfFile,"%64s\n",S5Mysql.User) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Mysql server (user):        %64s.",S5Mysql.User);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"mysql_profile_pass\0",sizeof("mysql_profile_pass\0") - 1) ) {
      if( fscanf(S5ConfFile,"%64s\n",S5Mysql.Pass) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Mysql server (pass):        %64s.",S5Mysql.Pass);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"mysql_profile_sqlstring\0",sizeof("mysql_profile_sqlstring\0") - 1) ) {
      i=0;
      while( (S5Mysql.SqlString[i++]=fgetc(S5ConfFile)) != '\n' && i < 64 );
      S5Mysql.SqlString[--i]=0;

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Mysql server (sqlstring):        %64s.",S5Mysql.SqlString);
        LOGUPDATE()
      }
    }
#endif
    /*
     * Parse the following directory information directives:
     *
     * <ldap_profile_ip>
     * <ldap_profile_port>
     * <ldap_profile_base>
     * <ldap_profile_filter>
     * <ldap_profile_attribute>
     * <ldap_profile_dn>
     * <ldap_profile_pass>
     * <ldap_profile_domain>
     */
    else if( STREQ(confString,"ldap_profile_ip\0",sizeof("ldap_profile_ip\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Ldap[NLdapStore].IP) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      SS5SocksOpt.Profiling=LDAP_PROFILING;

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (ip):        %64s.",S5Ldap[NLdapStore].IP);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_port\0",sizeof("ldap_profile_port\0") - 1) ) {
      if( fscanf(S5ConfFile,"%6s\n",S5Ldap[NLdapStore].Port) < 1 ) {
        ERRNO(0)
        return ERR;
      }
 
      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (prt):       %64s.",S5Ldap[NLdapStore].Port);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_base\0",sizeof("ldap_profile_base\0") - 1) ) {
      if( fscanf(S5ConfFile,"%64s\n",S5Ldap[NLdapStore].Base) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (base):      %64s.",S5Ldap[NLdapStore].Base);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_filter\0",sizeof("ldap_profile_filter\0") - 1) ) {
      if( fscanf(S5ConfFile,"%32s\n",S5Ldap[NLdapStore].Filter) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (filter):    %64s.",S5Ldap[NLdapStore].Filter);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_attribute\0",sizeof("ldap_profile_attribute\0") - 1) ) {
      if( fscanf(S5ConfFile,"%32s\n",S5Ldap[NLdapStore].Attribute) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (attribute): %64s.",S5Ldap[NLdapStore].Attribute);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_dn\0",sizeof("ldap_profile_dn\0") - 1) ) {
      if( fscanf(S5ConfFile,"%64s\n",S5Ldap[NLdapStore].Dn) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (dn):        %64s.",S5Ldap[NLdapStore].Dn);
        LOGUPDATE()
      }
    }
    else if( STREQ(confString,"ldap_profile_pass\0",sizeof("ldap_profile_pass\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Ldap[NLdapStore].Pass) < 1 ) {
        ERRNO(0)
        return ERR;
      }
    }
    else if( STREQ(confString,"ldap_netbios_domain\0",sizeof("ldap_netbios_domain\0") - 1) ) {
      if( fscanf(S5ConfFile,"%16s\n",S5Ldap[NLdapStore].NtbDomain) < 1 ) {
        ERRNO(0)
        return ERR;
      }

      if( (m != PARSE_CONFIG) && SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] Directory (netbios_domain):        %52s.",S5Ldap[NLdapStore].NtbDomain);
        LOGUPDATE()
      }

      if( NLdapStore < MAXLDAPSTORE ) {
        NLdapStore++;
      }
      else if( m != PARSE_CONFIG )  {
        snprintf(logString,256 - 1,"[ERRO] Maximum number of directory store lines reached: %d.",MAXLDAPSTORE);
        LOGUPDATE()
      }
    }
    /* 
     * Parse socks server OPTIONS
     */        
    else if( STREQ(confString,"set\0",sizeof("set\0") - 1) ) {
      fscanf(S5ConfFile,"%32s\n",confString);

      if( STREQ(confString,"SS5_DNSORDER\0",sizeof("SS5_DNSORDER\0") - 1) ) {
        SS5SocksOpt.DnsOrder = OK;
      }
      else if( STREQ(confString,"SS5_CONSOLE\0",sizeof("SS5_CONSOLE\0") - 1) ) {
        SS5SocksOpt.IsConsole = OK;
      }
      else if( STREQ(confString,"SS5_SRV\0",sizeof("SS5_SRV\0") - 1) ) {
        SS5SocksOpt.IsSrvmgr = OK;
      }
      else if( STREQ(confString,"SS5_LDAP_TIMEOUT\0",sizeof("SS5_LDAP_TIMEOUT\0")  - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.LdapTimeout = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_LDAP_BASE\0",sizeof("SS5_LDAP_BASE\0") - 1) ) {
        SS5SocksOpt.LdapCriteria = LDAP_BASE;
      }
      else if( STREQ(confString,"SS5_LDAP_FILTER\0",sizeof("SS5_LDAP_FILTER\0") - 1) ) {
        SS5SocksOpt.LdapCriteria = LDAP_FILTER;
      }
      else if( STREQ(confString,"SS5_NETBIOS_DOMAIN\0",sizeof("SS5_NETBIOS_DOMAIN\0") - 1) ) {
        SS5SocksOpt.LdapNetbiosDomain = OK;
      }
      else if( STREQ(confString,"SS5_PAM_AUTH\0",sizeof("SS5_PAM_AUTH\0") - 1) ) {
        SS5SocksOpt.Authentication = PAM_AUTHENTICATION;
      }
      else if( STREQ(confString,"SS5_RADIUS_AUTH\0",sizeof("SS5_RADIUS_AUTH\0") - 1) ) {
        SS5SocksOpt.Authentication = RADIUS_AUTHENTICATION;
      }
      else if( STREQ(confString,"SS5_RADIUS_INTERIM_INT\0",sizeof("SS5_RADIUS_INTERIM_INT\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.RadIntUpdInterval = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_RADIUS_INTERIM_TIMEOUT\0",sizeof("SS5_RADIUS_INTERIM_TIMEOUT\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.RadInterimTimeout = atoi(optionString);
      }                                             
      else if( STREQ(confString,"SS5_AUTHCACHEAGE\0",sizeof("SS5_AUTHCACHEAGE\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.AuthCacheAge = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_AUTHOCACHEAGE\0",sizeof("SS5_AUTHOCACHEAGE\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.AuthoCacheAge = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_STICKYAGE\0",sizeof("SS5_STICKYAGE\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.StickyAge = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_STICKY_SESSION\0",sizeof("SS5_STICKY_SESSION\0") - 1) ) {
        SS5SocksOpt.Sticky = OK;
      }
      else if( STREQ(confString,"SS5_VERBOSE\0",sizeof("SS5_VERBOSE\0") - 1) ) {
        SS5SocksOpt.Verbose = OK;
      }
      else if( STREQ(confString,"SS5_DEBUG\0",sizeof("SS5_DEBUG\0") - 1) ) {
        SS5SocksOpt.Debug = OK;
      }
      else if( STREQ(confString,"SS5_STIMEOUT\0",sizeof("SS5_STIMEOUT\0") - 1) ) {
        fscanf(S5ConfFile,"%12s\n",optionString);
        SS5SocksOpt.SessionIdleTimeout = atol(optionString);
      }
      else if( STREQ(confString,"SS5_ATIMEOUT\0",sizeof("SS5_ATIMEOUT\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.AcceptTimeout = atoi(optionString);
      }
      else if( STREQ(confString,"SS5_SUPAKEY\0",sizeof("SS5_SUPAKEY\0") - 1) ) {
        fscanf(S5ConfFile,"%16s\n",SS5SocksOpt.SupaKey);
        if( strlen((const char *)SS5SocksOpt.SupaKey) != 16 ) {
          snprintf(logString,256 - 1,"[ERR] Option SUPAKEY must be 16 characters long.");
          LOGUPDATE()
          return ERR;
        }
      }
      else if( STREQ(confString,"SS5_SYSLOG_FACILITY\0",sizeof("SS5_SYSLOG_FACILITY\0") - 1) ) {
        fscanf(S5ConfFile,"%32s\n",pcf.slogFacil);

        if( STREQ(pcf.slogFacil,"LOG_LOCAL0\0",sizeof("LOG_LOCAL0\0") - 1) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL0;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL1\0",sizeof("LOG_LOCAL1\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL1;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL2\0",sizeof("LOG_LOCAL2\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL2;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL3\0",sizeof("LOG_LOCAL3\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL3;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL4\0",sizeof("LOG_LOCAL4\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL4;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL5\0",sizeof("LOG_LOCAL5\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL5;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL6\0",sizeof("LOG_LOCAL6\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL6;
        else if( STREQ(pcf.slogFacil,"LOG_LOCAL7\0",sizeof("LOG_LOCAL7\0")) )
          SS5SocksOpt.SyslogFa=LOG_LOCAL7;
        else {
          snprintf(logString,256 - 1,"[ERR] Option SS5_SYSLOG_FACILITY not valid.");
          LOGUPDATE()
          return ERR;
        }
      }
      else if( STREQ(confString,"SS5_SYSLOG_LEVEL\0",sizeof("SS5_SYSLOG_LEVEL\0") - 1) ) {
        fscanf(S5ConfFile,"%32s\n",pcf.slogFacil);

        if( STREQ(pcf.slogFacil,"LOG_EMERG\0",sizeof("LOG_EMERG\0")) )
          SS5SocksOpt.SyslogLe=LOG_EMERG;
        else if( STREQ(pcf.slogFacil,"LOG_ALERT\0",sizeof("LOG_ALERT\0")) )
          SS5SocksOpt.SyslogLe=LOG_ALERT;
        else if( STREQ(pcf.slogFacil,"LOG_CRIT\0",sizeof("LOG_CRIT\0")) )
          SS5SocksOpt.SyslogLe=LOG_CRIT;
        else if( STREQ(pcf.slogFacil,"LOG_ERR\0",sizeof("LOG_ERR\0")) )
          SS5SocksOpt.SyslogLe=LOG_ERR;
        else if( STREQ(pcf.slogFacil,"LOG_WARNING\0",sizeof("LOG_WARNING\0")) )
          SS5SocksOpt.SyslogLe=LOG_WARNING;
        else if( STREQ(pcf.slogFacil,"LOG_NOTICE\0",sizeof("LOG_NOTICE\0")) )
          SS5SocksOpt.SyslogLe=LOG_NOTICE;
        else if( STREQ(pcf.slogFacil,"LOG_INFO\0",sizeof("LOG_INFO\0")) )
          SS5SocksOpt.SyslogLe=LOG_INFO;
        else if( STREQ(pcf.slogFacil,"LOG_DEBUG\0",sizeof("LOG_DEBUG\0")) )
          SS5SocksOpt.SyslogLe=LOG_DEBUG;
        else {
          snprintf(logString,256 - 1,"[ERR] Option SS5_SYSLOG_LEVEL not valid.");
          LOGUPDATE()
          return ERR;
        }
      }
      else if( STREQ(confString,"SS5_ICACHESERVER\0",sizeof("SS5_ICACHESERVER\0") - 1) ) {
        fscanf(S5ConfFile,"%16s\n",SS5SocksOpt.ICacheServer);
        if( strlen((const char *)SS5SocksOpt.ICacheServer) > 16 ) {
          snprintf(logString,256 - 1,"[ERR] Option ICACHESERVER too long.");
          LOGUPDATE()
          return ERR;
        }
      }
#ifdef SS5_USE_GSSAPI
      else if( STREQ(confString,"SS5_GSS_PRINC\0",sizeof("SS5_GSS_PRINC\0") - 1) ) {
        fscanf(S5ConfFile,"%64s\n",SS5SocksOpt.GssPrincipal);
      }
#endif
      else if( STREQ(confString,"SS5_PROCESSLIFE\0",sizeof("SS5_PROCESSLIFE\0") - 1) ) {
        fscanf(S5ConfFile,"%6s\n",optionString);
        SS5SocksOpt.PreforkProcessLife = atoi(optionString);

        if( SS5SocksOpt.PreforkProcessLife > MAXPREFORKPROCLIFE )
          SS5SocksOpt.PreforkProcessLife = MAXPREFORKPROCLIFE;
      }

      if( (m != PARSE_CONFIG) && VERBOSE() ) {
        snprintf(logString,256 - 1,"[VERB] Option %20s set.",confString);
        LOGUPDATE()
      }
    }
    else {
      if( m != PARSE_CONFIG ) {
        snprintf(logString,256 - 1,"[ERRO] Wrong line \"%s\" in configuration file.",confString);
        LOGUPDATE()
      }
      return ERR;
    }
  }
  /*
   * Show objects loaded
   */
  if( m != PARSE_CONFIG ) {
    SS5Modules.mod_logging.Logging("[INFO] Loading configuration completed");
    if( SS5SocksOpt.Verbose ) {
      snprintf(logString,256 - 1,"[VERB] N. %6d permit    lines loaded.",_tmp_NAclList);
      LOGUPDATE()
      snprintf(logString,256 - 1,"[VERB] N. %6d method    lines loaded.",_tmp_NMethodList);
      LOGUPDATE()
      snprintf(logString,256 - 1,"[VERB] N. %6d proxy     lines loaded.",_tmp_NProxyList);
      LOGUPDATE()
      snprintf(logString,256 - 1,"[VERB] N. %6d bandwidth lines loaded.",_tmp_NBandwidthList);
      LOGUPDATE()
      snprintf(logString,256 - 1,"[VERB] N. %6d dump      lines loaded.",_tmp_NDumpList);
      LOGUPDATE()
      snprintf(logString,256 - 1,"[VERB] N. %6d virtual   lines loaded.",_tmp_NReal);
      LOGUPDATE()
    }
  }

  if( fclose(S5ConfFile) ) {
    if( m != PARSE_CONFIG ) 
      SS5Modules.mod_logging.Logging("[ERRO] Error closing configuration file.");

    return ERR;
  }

  /* 
   * Open HA socks server configuration file 
   */
  if( (S5PeerFile = fopen(S5PeersFile,"r")) == NULL ) {
    ERRNO(0)
  }
  else {
    /* 
     * Load socks server configuration information 
     */
    while( fscanf(S5PeerFile,"%255s",confString)!=EOF ) {
      /*
       * Skip commnents
       */
      if( confString[0] == '#' ) {
          while( fgetc(S5PeerFile) != '\n' );
      }
      /*
       * Parse <route> directive
       */
      else if( STREQ(confString,"route\0",sizeof("route\0") - 1) ) {
  
        if( _tmp_NRouteList < MAXROUTELIST ) {
          if( fscanf(S5PeerFile,"%20s %16s %64s %1s\n",pcf.srcAddr,pcf.srcIf,pcf.group,pcf.routeDir) < 3 ) {
            ERRNO(0)
            return ERR;
          }
          switch(pcf.routeDir[0]) {
            case '-':    sdr=SRC_ROUTE;    break;
            case 's':    sdr=SRC_ROUTE;    break;
            case 'd':    sdr=DST_ROUTE;    break;
            default:     SS5Modules.mod_logging.Logging("[ERRO] Type unknown in route line.");    return ERR;    break;
          }
  
          srcMask=S5GetNetmask(pcf.srcAddr);
          in.s_addr=inet_addr(pcf.srcIf);
          SS5Modules.mod_socks5.AddRoute(OFFLINE,inet_network(pcf.srcAddr),in.s_addr,pcf.group,32-srcMask,sdr);
          _tmp_NRouteList++;
  
          SS5SocksOpt.IsRoute = OK;
        }
        else {
          if( m != PARSE_CONFIG )  {
            snprintf(logString,256 - 1,"[ERRO] Maximum number of route lines reached: %d.",MAXROUTELIST);
            LOGUPDATE()
          }
          return ERR;
        }
      }
  
    }
  
    if( fclose(S5PeerFile) ) {
      if( m != PARSE_CONFIG ) 
        SS5Modules.mod_logging.Logging("[ERRO] Error closing HA configuration file.");
  
      return ERR;
    }

    /*
     * Show HA objects loaded
     */
    if( m != PARSE_CONFIG ) {
      SS5Modules.mod_logging.Logging("[INFO] Loading HA configuration completed");
      if( SS5SocksOpt.Verbose ) {
        snprintf(logString,256 - 1,"[VERB] N. %6d route   lines loaded.",_tmp_NRouteList);
        LOGUPDATE()
      }
    }
  }

  return OK;
}

UINT S5SwitchConfData( void )
{
  register UINT count;

  /*
   * Switch Acl List
   */
  _old_S5AclList=S5AclList;
  S5AclList=_tmp_S5AclList;
  _tmp_S5AclList=NULL;

  NAclList=_tmp_NAclList;
  _tmp_NAclList=0;

  /*
   * Switch Method List
   */
  _old_S5MethodList=S5MethodList;
  S5MethodList=_tmp_S5MethodList;
  _tmp_S5MethodList=NULL;

  NMethodList=_tmp_NMethodList;
  _tmp_NMethodList=0;

  /*
   * Switch Bandwidth List
   */
  if( S5BandTableList != NULL  )
    for(count = 0;count < MAXBANDLIST;count++) {
      SS5Modules.mod_bandwidth.TransfBandTable( S5BandTableList[count] );
    }
  _old_S5BandTableList=S5BandTableList;
  S5BandTableList=_tmp_S5BandTableList;
  _tmp_S5BandTableList=NULL;

  NBandwidthList=_tmp_NBandwidthList;
  _tmp_NBandwidthList=0;

  /*
   * Switch Route List
   */
  _old_S5RouteList=S5RouteList;
  S5RouteList=_tmp_S5RouteList;
  _tmp_S5RouteList=NULL;

  NRouteList=_tmp_NRouteList;
  _tmp_NRouteList=0;

  /*
   * Switch Proxy List
   */
  _old_S5ProxyList=S5ProxyList;
  S5ProxyList=_tmp_S5ProxyList;
  _tmp_S5ProxyList=NULL;

  NProxyList=_tmp_NProxyList;
  _tmp_NProxyList=0;

  /*
   * Switch Dump List
   */
  _old_S5DumpList=S5DumpList;
  S5DumpList=_tmp_S5DumpList;
  _tmp_S5DumpList=NULL;

  NDumpList=_tmp_NDumpList;
  _tmp_NDumpList=0;

   /*
   * Switch Connection Table List
   */
  S5ConnectionTable._old_S5ConnectionEntry=S5ConnectionTable.S5ConnectionEntry;
  S5ConnectionTable.S5ConnectionEntry=S5ConnectionTable._tmp_S5ConnectionEntry;
  S5ConnectionTable._tmp_S5ConnectionEntry=NULL;

  NReal=_tmp_NReal;
  _tmp_NReal=0;

  return OK;
}

UINT S5AllocConfData( void )
{ 
  register UINT count;

  if( (_tmp_S5AclList = calloc(MAXACLLIST,      sizeof(struct  _S5AclNode *))) == NULL )
    return ERR;
  else
    for(count = 0;count < MAXACLLIST;count++)
      _tmp_S5AclList[count] = NULL;

  if( (_tmp_S5MethodList = calloc(MAXMETHODLIST,sizeof(struct  _S5MethodNode *))) == NULL )
    return ERR;
  else
    for(count = 0;count < MAXMETHODLIST;count++)
      _tmp_S5MethodList[count] = NULL;

  if( (_tmp_S5RouteList = calloc(MAXROUTELIST,  sizeof(struct  _S5RouteNode *))) == NULL )
    return ERR;
  else
    for(count = 0;count < MAXROUTELIST;count++)
      _tmp_S5RouteList[count] = NULL;

  if( (_tmp_S5ProxyList = calloc(MAXPROXYLIST,  sizeof(struct  _S5ProxyNode *))) == NULL )
    return ERR;
  else
    for(count = 0;count < MAXPROXYLIST;count++)
      _tmp_S5ProxyList[count] = NULL;

  if( SS5Modules.mod_dump_loaded ) {
    if( (_tmp_S5DumpList = calloc(MAXDUMPLIST,  sizeof(struct  _S5DumpNode *))) == NULL )
      return ERR;
    else
      for(count = 0;count < MAXDUMPLIST;count++)
        _tmp_S5DumpList[count] = NULL;
  }

  if( SS5Modules.mod_bandwidth_loaded ) {
    if( (_tmp_S5BandTableList = calloc(MAXBANDLIST,  sizeof(struct  _S5BandTableNode *))) == NULL )
      return ERR;
    else
      for(count = 0;count < MAXBANDLIST;count++)
        _tmp_S5BandTableList[count] = NULL;
  }

  if( SS5Modules.mod_balancing_loaded ) {
    if( (S5ConnectionTable._tmp_S5ConnectionEntry = calloc(MAX_ENTRY_REAL,  sizeof(struct _S5ConnectionEntry *))) == NULL )
      return ERR;
    else
      for(count = 0; count < MAX_ENTRY_REAL; count++)
        S5ConnectionTable._tmp_S5ConnectionEntry[count] = NULL;
  }
  return OK;
}

UINT S5FreeConfData( void )
{
  register UINT index;

  /*
   * Free ACL memory buffer
   */
  if( _old_S5AclList != NULL ) {
    for(index=0;index<MAXACLLIST;index++) {
      SS5Modules.mod_authorization.FreeAcl(&_old_S5AclList[index]);
      _old_S5AclList[index]=NULL;
    }
    free(_old_S5AclList);
    _old_S5AclList=NULL;
  }

  /*
   * Free Method memory buffer
   */
  if( _old_S5MethodList != NULL ) {
    for(index=0;index<MAXMETHODLIST;index++) {
      SS5Modules.mod_socks5.FreeMethod(&_old_S5MethodList[index]);
      _old_S5MethodList[index]=NULL;
    }
    free(_old_S5MethodList);
    _old_S5MethodList=NULL;
  }

  /*
   * Free BandTable memory buffer
   */
  if( _old_S5BandTableList != NULL ) {
    for(index=0;index<MAXBANDLIST;index++) {
      SS5Modules.mod_bandwidth.FreeBandTable(&_old_S5BandTableList[index]);
      _old_S5BandTableList[index]=NULL;
    }
    free(_old_S5BandTableList);
    _old_S5BandTableList=NULL;
  }

  /*
   * Free Authentication Cache
   */
  for(index=0;index<MAXAUTHCACHELIST;index++) {
      SS5Modules.mod_authentication.FreeAuthCache(&S5AuthCacheList[index]);
      S5AuthCacheList[index]=NULL;
  }

  /*
   * Free route ACL memory buffer
   */
  if( _old_S5RouteList != NULL ) {
    for(index=0;index<MAXROUTELIST;index++) {
      SS5Modules.mod_socks5.FreeRoute(&_old_S5RouteList[index]);
      _old_S5RouteList[index]=NULL;
    }
    free(_old_S5RouteList);
    _old_S5RouteList=NULL;
  }

  /*
   * Free Authorization Cache: DISABLE SINCE 3.8.x
   */
  /*for(index=0;index<MAXAUTHOCACHELIST;index++) {
      SS5Modules.mod_authorization.FreeAuthoCache(&S5AuthoCacheList[index]);
      S5AuthoCacheList[index]=NULL;
  }*/

  /*
   * Free upstream proxy LIST memory buffer
   */
  if( _old_S5ProxyList != NULL ) {
    for(index=0;index<MAXPROXYLIST;index++) {
      SS5Modules.mod_socks5.FreeProxy(&_old_S5ProxyList[index]);
      _old_S5ProxyList[index]=NULL;
    }
    free(_old_S5ProxyList);
    _old_S5ProxyList=NULL;
  }

  /*
   * Free dump LIST memory buffer
   */
  if( SS5Modules.mod_dump_loaded ) {
    if( _old_S5DumpList != NULL ) {
      for(index=0;index<MAXDUMPLIST;index++) {
        SS5Modules.mod_dump.FreeDump(&_old_S5DumpList[index]);
        _old_S5DumpList[index]=NULL;
      }
      free(_old_S5DumpList);
      _old_S5DumpList=NULL;
    }
  }

   /*
   * Free connection table LIST memory buffer
   */
  if( SS5Modules.mod_balancing_loaded ) {
    if( S5ConnectionTable._old_S5ConnectionEntry != NULL ) {
      for(index=0;index<MAX_ENTRY_REAL;index++) {
        SS5Modules.mod_balancing.FreeConnectionTable(S5ConnectionTable._old_S5ConnectionEntry[index]);
        S5ConnectionTable._old_S5ConnectionEntry[index]=NULL;
      }
      free(S5ConnectionTable._old_S5ConnectionEntry);
      S5ConnectionTable._old_S5ConnectionEntry=NULL;
    }

    for(index=0;index<MAXSTICKYLIST;index++)  {
      SS5Modules.mod_balancing.FreeAffinity(&S5StickyList[index]);
      S5StickyList[index]=NULL;
    }
  }

  return OK;
}


UINT S5GetIf( void )
{
  struct ifreq ifr_x[MAXIF],ifr_y;
  struct ifconf ifc;
  struct sockaddr_in *ssin;

  char logString[256];

  int sockfd;

  UINT index;

#ifdef FREEBSD
  unsigned short int len,i;
  struct ifreq ifreq,*ifr;
  char buf[8192];
  char * ptr;
#endif

  SS5Modules.mod_logging.Logging("[INFO] Loading network interfaces.");

  NInterF=0;
  if( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) ==-1 ) {
    SS5Modules.mod_logging.Logging("[ERRO] Error creating socket while loading network interface.");
    return ERR;
  }

#ifdef FREEBSD
  ifc.ifc_len = sizeof buf;
  ifc.ifc_buf = buf;
#else
  ifc.ifc_len = MAXIF * sizeof(struct ifreq);
  ifc.ifc_req = ifr_x;
#endif

  index = ioctl(sockfd, SIOCGIFCONF, &ifc);

  NInterF=ifc.ifc_len / sizeof(struct ifreq);
  if( NInterF == MAXIF ) {
    snprintf(logString,128,"[WARN] Maximum number of network interfaces reached: %d (Not all interfaces will be used).",NInterF);
    LOGUPDATE()
    NInterF = MAXIF;
  }
#ifdef FREEBSD
        ifr = ifc.ifc_req;
        ifreq.ifr_name[0] = '\0';
        for (ptr = buf,index=0; ptr < buf + ifc.ifc_len,index++; ) {
           ifr = (struct ifreq *) ptr;

           if (ifr->ifr_addr.sa_len > sizeof(struct sockaddr))
                len = ifr->ifr_addr.sa_len;
           else
                len = sizeof(struct sockaddr);
           ptr += sizeof(ifr->ifr_name) + len;
           strncpy(ifr_y.ifr_name,ifr->ifr_name,sizeof(ifr_y.ifr_name));
#else
  for (index = 0; index < NInterF; index++) {
    strncpy(ifr_y.ifr_name,ifr_x[index].ifr_name,sizeof(ifr_y.ifr_name));
#endif
    /* 
     * Look for socks server ip address  
     */
#ifdef FREEBSD
    if( ioctl(sockfd, SIOCAIFADDR ,&ifr_y) < 0 ) {
#else
    if( ioctl(sockfd, SIOCGIFADDR ,(char *) &ifr_y) == -1 ) {
#endif
      ERRNO(0)
      return ERR;
    }

    ssin = (struct sockaddr_in *)&ifr_y.ifr_addr;

    if( (S5Interface[index]=(struct _S5Interface *)calloc( 1, sizeof( struct _S5Interface ))) == NULL )
      return ERR;
    else
      strncpy(S5Interface[index]->IP,(char *)inet_ntoa(ssin->sin_addr),sizeof(S5Interface[index]->IP));

    /* 
     * Look for socks server ip netmask
    */
#ifndef FREEBSD
    if( ioctl(sockfd, SIOCGIFNETMASK ,(char *) &ifr_y) == -1) {
      ERRNO(0)
      return ERR;
    }
#endif

#ifdef FREEBSD
    ssin = (struct sockaddr_in *)&ifr_y.ifr_addr;
#endif

    #ifdef LINUX
    ssin = (struct sockaddr_in *)&ifr_y.ifr_netmask;
    #endif

    #ifdef SOLARIS
    ssin = (struct sockaddr_in *)&ifr_y.ifr_addr;
    #endif

    strncpy(S5Interface[index]->NetMask,(char *)inet_ntoa(ssin->sin_addr),sizeof(S5Interface[index]->NetMask));
    if( SS5SocksOpt.Verbose ) {
      snprintf(logString,128,"[VERB] Interface %12s %16s %16s loaded.",ifr_x[index].ifr_name,
              S5Interface[index]->IP,S5Interface[index]->NetMask);
      LOGUPDATE()
    }
  }
  close(sockfd);

  /*
   * Module LOGGING: call --> Logging
   */  
  if( SS5SocksOpt.Verbose ) {
    snprintf(logString,128,"[VERB] N. %6d network interfaces loaded.",NInterF);
    LOGUPDATE()
  }

  return OK;
}

void S5Usage( void ) 
{
    fprintf(stderr, "[INFO] %s\n",SS5_VERSION);
    fprintf(stderr, "[INFO] %s\n\n",SS5_COPYRIGHT);
    fprintf(stderr, "[INFO] Usage incorrect...\n");
    fprintf(stderr, "[INFO] Usage: ss5 \n");
    fprintf(stderr, "[INFO]     [-s] Use syslog instead of ss5.log file.\n");
    fprintf(stderr, "[INFO]     [-v] Print version information.\n");
    fprintf(stderr, "[INFO]     [-n] Prefork processes (not supported with -t option).\n");
    fprintf(stderr, "[INFO]     [-t] Threaded mode.\n");
    fprintf(stderr, "[INFO]     [-u] Username for ss5 execution.\n");
    fprintf(stderr, "[INFO]     [-b] Bind interface.\n");
    fprintf(stderr, "[INFO]     [-c] Run syntax check for config file.\n");
    fprintf(stderr, "[INFO]     [-m] No logging.\n");
    fprintf(stderr, "[INFO]     [-p] Pid file pathname.\n");
    fprintf(stderr, "[INFO] Modules:\n");
    fprintf(stderr, "[INFO]     mod_socks5:      required\n");
    fprintf(stderr, "[INFO]     mod_authen:      required\n");
    fprintf(stderr, "[INFO]     mod_author:      required\n");
    fprintf(stderr, "[INFO]     mod_log:         required\n");
    fprintf(stderr, "[INFO]     mod_proxy:       required\n");
    fprintf(stderr, "[INFO]     mod_balance:     optional\n");
    fprintf(stderr, "[INFO]     mod_bandwidth:   optional\n");
    fprintf(stderr, "[INFO]     mod_dump:        optional\n");
    fprintf(stderr, "[INFO]     mod_filter:      optional\n");
    fprintf(stderr, "[INFO]     mod_socks4:      optional\n");
    fprintf(stderr, "[INFO]     mod_statistics:  optional\n");

    exit(-1);
}

void S5ReloadConfig( int sig )
{
  if( sig == SIGHUP )
    if( getppid() == 1 ) {
      LOCKMUTEXCO()
      S5LoadConfig(RELOAD_CONFIG);
      UNLOCKMUTEXCO()
    }
}

UINT S5GetNetmask(char *sa)
{
  register UINT i,j,k ;
  char nm[3];

  for(i=0;(sa[i]!='/') && (i<strlen(sa));i++);

  if( sa[i] == '/' ) {
    for(k=i+1,j=0;(k)<strlen(sa);k++,j++)
      nm[j]=sa[k];

    nm[j]='\0';
    sa[i]='\0';

    return atoi(nm);
  }

  return 32;
}

ULINT S5GetRange(char *po)
{
  register UINT i,j,k ;
  char min[6],max[6];
  ULINT p;

  if( po[0] == '-' )
    return 4294901760UL; /* (65535 << 16);  0 - 65535  all ports */
  else {

    for(i=0;(po[i]!='-') && (i<strlen(po));i++);

    if( po[i] == '-' ) {

      /* Get min port */
      for(k=0;k<i;k++)
        min[k]=po[k];
      min[k]='\0';

      /* Get max port */
      for(k=i+1,j=0;k<strlen(po);k++,j++)
        max[j]=po[k];
      max[j]='\0';

      p=atoi(max);
      p <<=16;
      p +=atoi(min);

      return p;
    }
    else
      return atoi(po);
  }
  return ERR;
}

ULINT S5StrHash( char *s )
{
  register UINT i;
  UINT len;
  ULINT hashVal = 0;

  len=strlen(s);
  for(i=0; i<len;i++)
    hashVal= 37*hashVal + s[i];

  return hashVal;

}

