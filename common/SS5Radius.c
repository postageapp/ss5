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
#include "SS5Mod_authentication.h"
#include "SS5Radius.h"


UINT S5RadiusAuth( struct _SS5ClientInfo *ci, pid_t pid ) {

  char logString[256];

  register UINT i; 

  fd_set fdset;

  struct timeval tv;

  UINT fd,
               len,
               sid;

  int          offset,
               radiusSocket,
               packetLen;

  MD5_CTX md5;

  uint8_t md5digest[MD5_DIGEST_LENGTH];

  struct in_addr in;
  struct sockaddr_in da_sin,sa_sin;

  unsigned char *radiusAttrib;

  char buf[32],trash[32];

  unsigned char radiusReqVector[VECTOR_LEN];
  unsigned char radiusRespVector[VECTOR_LEN];
  unsigned char radiusPacket[MAX_PACKET_LEN];

  /* 
   * Build RADIUS Authentication request
   */
  memset(radiusPacket,0,sizeof(radiusPacket));
  srand((unsigned)time(NULL)*pid);
  sid = (rand() % 0xFF);

  radiusPacket[OFF_CODE]       = 1;
  radiusPacket[OFF_PACKET_ID]  = sid;

  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBU] Radius request session id %d.",pid,radiusPacket[OFF_PACKET_ID]);
    SS5Modules.mod_logging.Logging(logString);
  }

  srand((unsigned)time(NULL)*pid);
  for(i=0;i<VECTOR_LEN;i++) {
    radiusReqVector[i]=(rand() % 0xFF);
  }

  memcpy(radiusPacket + OFF_VECTOR, radiusReqVector,VECTOR_LEN);

  len=strlen(ci->Username);
  radiusPacket[HEADER_LEN] = 1;
  radiusPacket[HEADER_LEN + 1] = len+2;

  memcpy(radiusPacket + HEADER_LEN + 2,ci->Username,len);

  MD5_Init(&md5);

  MD5_Update(&md5, S5Radius.Secret,strlen(S5Radius.Secret) );
  MD5_Update(&md5, radiusPacket + OFF_VECTOR, VECTOR_LEN);

  MD5_Final(&md5digest[0], &md5);

  for(i = 0; i < sizeof(md5digest); i++)
    if( i < strlen(ci->Password))
      md5digest[i] ^= ci->Password[i];

  radiusPacket[HEADER_LEN + 2 + len]     = 2;
  radiusPacket[HEADER_LEN + 2 + len + 1] = sizeof(md5digest) + 2;

  memcpy(radiusPacket + HEADER_LEN + 2 + len + 2,md5digest,sizeof(md5digest));

  packetLen = HEADER_LEN + 2 + len + 2 + sizeof(md5digest);
  SETPLEN_R(radiusPacket,packetLen,OFF_PACKET_LEN)

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(S5Radius.AuthPort);
  da_sin.sin_addr.s_addr = inet_addr((char *)S5Radius.IP);

  /*
   * Create Radius socket
   */
  len=sizeof(struct sockaddr_in);

  if ( (radiusSocket = socket(AF_INET,SOCK_DGRAM, 0)) == -1)
    return ERR;

  /*
   * Send RADIUS Authentication request
   */
  IFLINUX( if( sendto(radiusSocket, radiusPacket, packetLen, MSG_NOSIGNAL, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
  IFSOLARIS( if( sendto(radiusSocket, radiusPacket, packetLen, 0, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )

    close(radiusSocket);
    return ERR;
  }

  /*
   * Receive RADIUS Authentication response 
   */
  FD_ZERO(&fdset);
  FD_SET(radiusSocket,&fdset);

  tv.tv_sec=RADIUS_TIMEOUT;
  tv.tv_usec=0;

  if( (fd=select(radiusSocket+1,&fdset,NULL,NULL,&tv)) ) {
    if( FD_ISSET(radiusSocket,&fdset) ) {

      if( (packetLen=recvfrom(radiusSocket,radiusPacket,sizeof(radiusPacket),0, (struct sockaddr *)&sa_sin,
                             (socklen_t *)&len)) == -1 ) {

        close(radiusSocket);
        return ERR;
      }
    }
  }
  else {
    /* 
     * If primary radius server fails, try secondary radius server if set
     */
    len=sizeof(struct sockaddr_in);
    da_sin.sin_addr.s_addr = inet_addr((char *)S5Radius.IPBck);

    /*
     * Send RADIUS Authentication request to secondary server
     */
    IFLINUX( if( sendto(radiusSocket, radiusPacket, packetLen, MSG_NOSIGNAL, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
    IFSOLARIS( if( sendto(radiusSocket, radiusPacket, packetLen, 0, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )

      close(radiusSocket);
      return ERR;
    }

    /*
     * Receive RADIUS Authentication response from secondary server
     */
    FD_ZERO(&fdset);
    FD_SET(radiusSocket,&fdset);
  
    tv.tv_sec=RADIUS_TIMEOUT;
    tv.tv_usec=0;
  
    memset(radiusPacket,0,sizeof(radiusPacket));
  
    if( (fd=select(radiusSocket+1,&fdset,NULL,NULL,&tv)) ) {
      if( FD_ISSET(radiusSocket,&fdset) ) {
  
        if( (packetLen=recvfrom(radiusSocket,radiusPacket,sizeof(radiusPacket),0, (struct sockaddr *)&sa_sin,
                               (socklen_t *)&len)) == -1 ) {
  
          close(radiusSocket);
          return ERR;
        }
      }
    }
    else {
      /* 
       * Radius timeout expired
       */
      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Radius authentication response TIMEOUT.",pid);
        SS5Modules.mod_logging.Logging(logString);
      }
      close(radiusSocket);
      return ERR;
    }
  }


  memcpy(radiusRespVector,radiusPacket + OFF_VECTOR,VECTOR_LEN);

  MD5_Init(&md5);

  MD5_Update(&md5, radiusPacket, 4);
  MD5_Update(&md5, radiusReqVector, VECTOR_LEN);

  offset=HEADER_LEN;

  /*
   * Parse RADIUS Authentication response attributes
   * and verify response authenticator
   */
  do {

    len=radiusPacket[offset + 1];

    if( len && (radiusAttrib=malloc(len)) != NULL ) {

      memcpy(radiusAttrib,radiusPacket + offset + 2,len - 2);
      radiusAttrib[len - 2]='\0';

      switch( radiusPacket[offset] ) {

        case ATT_Reply_Message:
          if( DEBUG() ) {
            snprintf(logString,256 - 1,"[%u] [DEBU] Radius Reply-Message: %s.",pid,radiusAttrib);
            SS5Modules.mod_logging.Logging(logString);
          }
        break;

        case ATT_Framed_Route:
          GETADDR_R(radiusAttrib,in.s_addr,0)
          sscanf((char *)radiusAttrib,"%32s %16s",trash,buf);

          ci->framedRoute.sin_addr.s_addr=inet_addr(buf);
          if( DEBUG() ) {
            snprintf(logString,256 - 1,"[%u] [DEBU] Radius Framed_Route bind address set to: %s.",pid,buf);
            SS5Modules.mod_logging.Logging(logString);
          }
        break;

        case ATT_Idle_Timeout:
          GETADDR(radiusAttrib,SS5SocksOpt.RadSessionIdleTimeout,0)
          if( DEBUG() ) {
            snprintf(logString,256 - 1,"[%u] [DEBU] Radius Idle-Timeout set to: %lu.",pid,SS5SocksOpt.RadSessionIdleTimeout);
            SS5Modules.mod_logging.Logging(logString);
          }
        break;

        case ATT_Session_Timeout:
          GETADDR(radiusAttrib,SS5SocksOpt.RadSessionTimeout,0)
          if( DEBUG() ) {
            snprintf(logString,256 - 1,"[%u] [DEBU] Radius Session-Timeout set to: %lu.",pid,SS5SocksOpt.RadSessionTimeout);
            SS5Modules.mod_logging.Logging(logString);
          }
        break; 

        case ATT_Acct_Interim_Interval:
          GETADDR(radiusAttrib,SS5SocksOpt.RadIntUpdInterval,0)
          if( DEBUG() ) {
            snprintf(logString,256 - 1,"[%u] [DEBU] Radius Interim-Interval set to: %lu.",pid,SS5SocksOpt.RadIntUpdInterval);
            SS5Modules.mod_logging.Logging(logString);
          }
        break; 
      }

      offset += len;

      free(radiusAttrib);
    }

  } while(offset<packetLen);

  MD5_Update(&md5, radiusPacket+20, packetLen - 20);
  MD5_Update(&md5, S5Radius.Secret,strlen(S5Radius.Secret) );

  MD5_Final(&md5digest[0], &md5);

  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBU] Radius response code %d.",pid,radiusPacket[OFF_CODE]);
    SS5Modules.mod_logging.Logging(logString);

    snprintf(logString,256 - 1,"[%u] [DEBU] Radius response session id %d.",pid,radiusPacket[OFF_PACKET_ID]);
    SS5Modules.mod_logging.Logging(logString);
  }

  /* 
   * Verify session id
   */
  if( radiusPacket[OFF_PACKET_ID] != sid ) {
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] Radius session id does not match.",pid);
      SS5Modules.mod_logging.Logging(logString);
    }

    close(radiusSocket);
    return ERR;
  }

  /* 
   * Verify radius authentication response
   */
  if( radiusPacket[OFF_CODE] == Access_Accept ) {
    /* 
     * Verify radius authenticator vector
     */
    for(i = 0; i < VECTOR_LEN; i++) {
      if( md5digest[i] != radiusRespVector[i] ) {
        if( VERBOSE() ) {
          snprintf(logString,256 - 1,"[%u] [VERB] Radius autenticator vector does not match.",pid);
          SS5Modules.mod_logging.Logging(logString);
        }

        close(radiusSocket);
        return ERR;
      }
    }
  }
  else {
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] Radius authentication failed.",pid);
      SS5Modules.mod_logging.Logging(logString);
    }

    close(radiusSocket);
    return ERR;
  }

  close(radiusSocket);

  /*
   * Save session id for accounting
   */
  ci->sid=sid;

  return OK;

}


UINT S5RadiusAcct( struct _SS5ClientInfo *ci, unsigned long cmd, pid_t pid ) {

  char logString[256];

  register UINT i; 

  fd_set fdset;

  struct timeval tv;

  UINT offset,
               fd,len,
               sid;

  int          radiusSocket,
               packetLen;

  MD5_CTX md5;

  uint8_t md5digest[MD5_DIGEST_LENGTH];

  unsigned char radiusTmp[16];

  unsigned char radiusReqVector[VECTOR_LEN];
  unsigned char radiusRespVector[VECTOR_LEN];
  unsigned char radiusPacket[MAX_PACKET_LEN];
  unsigned char radiusZeroVector[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

  struct sockaddr_in da_sin,sa_sin;
  
  /*
   * Build RADIUS Accounting request
   */
  memset(radiusPacket,0,sizeof(radiusPacket));
  sid = ci->sid;

  radiusPacket[OFF_CODE]      = Accounting_Request; 
  radiusPacket[OFF_PACKET_ID] = ci->sid;

  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBU] Radius accounting request session id %d.",pid,radiusPacket[OFF_PACKET_ID]);
    SS5Modules.mod_logging.Logging(logString);
  }

  /*
   * Add RADIUS attributes:
   *
   *  User-Name
   *  Acct-Session-Id
   *  NAS-Port
   *  Acct-Status-Type
   *  Acct-Session-Time
   *  Acct-Delay-Time
   *  Acct-Input-Octets
   *  Acct-Output-Octets
   *  Acct-CallingStationId
   *
   */

  offset=HEADER_LEN;

  /* User-Name */
  len=strlen(ci->Username);
  radiusPacket[offset]=ATT_User_Name;
  radiusPacket[offset + 1]=len + 2;
  memcpy(radiusPacket + offset + 2,ci->Username,len);
  offset = offset + len + 2;

  /* Acct-Session-Id */
  radiusPacket[offset]=ATT_Acct_Session_Id;
  radiusPacket[offset + 1]=5;
  srand((unsigned)time(NULL)*pid);
  if( cmd == ST_Start ) {
    snprintf((char *)radiusTmp,16 - 1,"%u\n",(rand() % 0xFF));
    memcpy(radiusPacket + offset + 2,radiusTmp,3);
  }
  else {
    memcpy(radiusPacket + offset + 2,ci->radiusTmp,3);
  }
  offset = offset + 5;

  /* NAS-Port */
  radiusPacket[offset] = ATT_NAS_Port;
  radiusPacket[offset + 1] = 6;
  SETXVAL_R(radiusPacket,SOCKS5_PORT,offset + 2)
  offset = offset + 6;

  /* Acct-Status-Type */
  radiusPacket[offset]=ATT_Acct_Status_Type;
  radiusPacket[offset + 1]=6;
  SETXVAL_R(radiusPacket,cmd,offset + 2)
  offset = offset + 6;

  /* Acct-Session-Time */
  radiusPacket[offset] = ATT_Acct_Session_Time;
  radiusPacket[offset + 1] = 6;
  if( cmd == ST_Interim_Update  || cmd == ST_Stop ) {
    SETXVAL_R(radiusPacket,ci->sessionTime,offset + 2)
  }
  else {
    SETXVAL_R(radiusPacket,0,offset + 2)
  }
  offset = offset + 6;

  /* Acct-Delay-Time */
  radiusPacket[offset]=ATT_Acct_Delay_Time;
  radiusPacket[offset + 1]=6;
  SETXVAL_R(radiusPacket,0,offset + 2)
  offset = offset + 6;

  /* Acct-Input-Octets */
  radiusPacket[offset]=ATT_Acct_Input_Octets;
  radiusPacket[offset + 1]=6;
  SETXVAL_R(radiusPacket,ci->oPacket,offset + 2)
  offset = offset + 6;

  /* Acct-Output-Octets */
  radiusPacket[offset]=ATT_Acct_Output_Octets;
  radiusPacket[offset + 1]=6;
  SETXVAL_R(radiusPacket,ci->iPacket,offset + 2)
  offset = offset + 6;

  /* Acct-CallingStationId */
  radiusPacket[offset]=ATT_Calling_Station_Id;
  radiusPacket[offset + 1]=strlen(ci->SrcAddr) + 2;
  memcpy(radiusPacket + offset + 2,ci->SrcAddr,strlen(ci->SrcAddr));
  offset = offset + strlen(ci->SrcAddr) + 2;

  packetLen= offset;
  SETPLEN_R(radiusPacket,packetLen,2)

  /*
   * Calculate vector
   */
  MD5_Init(&md5);

  MD5_Update(&md5, radiusPacket + OFF_CODE,4 );

  MD5_Update(&md5, radiusZeroVector,VECTOR_LEN );
  MD5_Update(&md5, radiusPacket + HEADER_LEN,packetLen - HEADER_LEN );

  MD5_Update(&md5, S5Radius.Secret,strlen(S5Radius.Secret) );

  MD5_Final(&md5digest[0], &md5);

  memcpy(radiusPacket + OFF_VECTOR,md5digest,VECTOR_LEN);
  memcpy(radiusReqVector,md5digest,VECTOR_LEN);

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(S5Radius.AcctPort);
  da_sin.sin_addr.s_addr = inet_addr((char *)S5Radius.IP);

  len=sizeof(struct sockaddr_in);

  /*
   * Create Radius socket
   */
  if ( (radiusSocket = socket(AF_INET,SOCK_DGRAM, 0)) == -1)
    return ERR;

  /*
   * Send RADIUS accounting request
   */
  IFLINUX( if( sendto(radiusSocket, &radiusPacket, packetLen, MSG_NOSIGNAL, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
  IFSOLARIS( if( sendto(radiusSocket, &radiusPacket, packetLen, 0, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )

    close(radiusSocket);
    return ERR;
  }

  /*
   * Receive RADIUS accounting response
   */
  FD_ZERO(&fdset);
  FD_SET(radiusSocket,&fdset);

  if( cmd == ST_Interim_Update && SS5SocksOpt.RadInterimTimeout != 9999 )
    tv.tv_sec=SS5SocksOpt.RadInterimTimeout;                   
  else                                                  
    tv.tv_sec=RADIUS_TIMEOUT; 

  tv.tv_usec=0;

  if( (fd=select(radiusSocket+1,&fdset,NULL,NULL,&tv)) ) {
    if( FD_ISSET(radiusSocket,&fdset) ) {

      if( (packetLen=recvfrom(radiusSocket,radiusPacket,sizeof(radiusPacket),0, (struct sockaddr *)&sa_sin,
                             (socklen_t *)&len)) == -1 ) {

        close(radiusSocket);
        return ERR;
      }
    }
  }
  else {
    /* 
     * If primary radius server fails, try secondary radius server if set
     */
    len=sizeof(struct sockaddr_in);
    da_sin.sin_addr.s_addr = inet_addr((char *)S5Radius.IPBck);

    /*
     * Send RADIUS accounting request to secondary server
     */
    IFLINUX( if( sendto(radiusSocket, &radiusPacket, packetLen, MSG_NOSIGNAL, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )
    IFSOLARIS( if( sendto(radiusSocket, &radiusPacket, packetLen, 0, (struct sockaddr *)&da_sin, (socklen_t)len ) == -1 ) { )

      close(radiusSocket);
      return ERR;
    }

    /*
     * Receive RADIUS accounting response from secondary server
     */
    FD_ZERO(&fdset);
    FD_SET(radiusSocket,&fdset);
  
    if( cmd == ST_Interim_Update && SS5SocksOpt.RadInterimTimeout != 9999 )
      tv.tv_sec=SS5SocksOpt.RadInterimTimeout;
    else
      tv.tv_sec=RADIUS_TIMEOUT;

    tv.tv_usec=0;
  
    memset(radiusPacket,0,sizeof(radiusPacket));
  
    if( (fd=select(radiusSocket+1,&fdset,NULL,NULL,&tv)) ) {
      if( FD_ISSET(radiusSocket,&fdset) ) {
  
        if( (packetLen=recvfrom(radiusSocket,radiusPacket,sizeof(radiusPacket),0, (struct sockaddr *)&sa_sin,
                               (socklen_t *)&len)) == -1 ) {
  
          close(radiusSocket);
          return ERR;
        }
      }
    }
    else {
      /*
       * Radius timeout expired
       */
      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Radius accounting response TIMEOUT.",pid);
        SS5Modules.mod_logging.Logging(logString);
      }
      close(radiusSocket);
      return ERR;
    }
  }

  memcpy(radiusRespVector,radiusPacket + OFF_VECTOR,VECTOR_LEN);

  MD5_Init(&md5);
 
  MD5_Update(&md5, radiusPacket, 4);
  MD5_Update(&md5, radiusReqVector, VECTOR_LEN);

  MD5_Update(&md5, radiusPacket + HEADER_LEN, packetLen - HEADER_LEN);
  MD5_Update(&md5, S5Radius.Secret,strlen(S5Radius.Secret) );

  MD5_Final(&md5digest[0], &md5);

  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBU] Radius accounting response code %d.",pid,radiusPacket[OFF_CODE]);
    SS5Modules.mod_logging.Logging(logString);

    snprintf(logString,256 - 1,"[%u] [DEBU] Radius accounting response session id %d.",pid,radiusPacket[OFF_PACKET_ID]);
    SS5Modules.mod_logging.Logging(logString);
  }
  /*
   * Verify session id
   */
  if( cmd == 1 ) {
    if( radiusPacket[OFF_PACKET_ID] != sid ) {
      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Radius accounting session id does not match.",pid);
        SS5Modules.mod_logging.Logging(logString);
      }

      close(radiusSocket);
      return ERR;
    }
  }
  else {
    if( radiusPacket[OFF_PACKET_ID] != ci->sid ) {
      if( VERBOSE() ) {
        snprintf(logString,256 - 1,"[%u] [VERB] Radius accounting session id does not match.",pid);
        SS5Modules.mod_logging.Logging(logString);
      }

      close(radiusSocket);
      return ERR;
    }
  }
  /*
   * Verify radius accounting response
   */
  if( radiusPacket[OFF_CODE] == Accounting_Response ) {
    /*
     * Verify radius acct authenticator vector
     */
    for(i = 0; i < VECTOR_LEN; i++) {
      if( md5digest[i] != radiusRespVector[i] ) {
        if( VERBOSE() ) {
          snprintf(logString,256 - 1,"[%u] [VERB] Radius accounting authenticator vector does not match.",pid);
          SS5Modules.mod_logging.Logging(logString);
        }

        close(radiusSocket);
        return ERR;
      }
    }
  }
  else {
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] Radius accounting failed.",pid);
      SS5Modules.mod_logging.Logging(logString);
    }

    close(radiusSocket);
    return ERR;
  }

  close(radiusSocket);

  if( cmd == ST_Start ) 
    strncpy((char *)ci->radiusTmp,(char *)radiusTmp,16);

  return OK;
}

