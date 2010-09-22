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
 * B
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include"SS5Main.h"
#include"SS5Debug.h"
#include"SS5Mod_log.h"


inline void S5DebugMethodInfo( pid_t pid, struct _SS5ClientInfo ci ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] MethodInfo->Ver       %5d.",pid,ci.Ver);          LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] MethodInfo->NMeth     %5d.",pid,ci.NMeth);        LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] MethodInfo->NoAuth    %5d.",pid,ci.NoAuth);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] MethodInfo->BasicAuth %5d.",pid,ci.BasicAuth);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] MethodInfo->Method    %5d.",pid,ci.Method);       LOGUPDATE()
}

inline void S5DebugAuthInfo( pid_t pid, struct _SS5ClientInfo ci ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] AuthInfo->Username %s.",pid,ci.Username);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] AuthInfo->Password xxxxxxxxxxxx.",pid);      LOGUPDATE()
}

inline void S5DebugRequestInfo( pid_t pid, struct _SS5RequestInfo ri ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->Ver       %5d.",pid,ri.Ver);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->Cmd       %5d.",pid,ri.Cmd);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->Rsv       %5d.",pid,ri.Rsv);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->ATyp      %5d.",pid,ri.ATyp);      LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->DstAddr   %s.",pid,ri.DstAddr);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] RequestInfo->DstPort   %5d.",pid,ri.DstPort);   LOGUPDATE()
}

inline void S5DebugUdpRequestInfo( pid_t pid, struct _SS5RequestInfo ri ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] UdpRequestInfo->Rsv       %5d.",pid,ri.udpRsv);        LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] UdpRequestInfo->Frag      %5d.",pid,ri.udpFrag);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] UdpRequestInfo->ATyp      %5d.",pid,ri.udpATyp);       LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] UdpRequestInfo->DstAddr   %s.",pid,ri.udpDstAddr);     LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] UdpRequestInfo->DstPort   %5d.",pid,ri.udpDstPort);    LOGUPDATE()
}

inline void S5DebugUpstreamInfo( pid_t pid, struct _SS5RequestInfo ri ) {
  char logString[256];

  struct in_addr in;

  in.s_addr=ri.upDstAddr;
  snprintf(logString,256 - 1,"[%u] [DEBU] UpstreamInfo->DstAddr       %s.",pid,(char *)inet_ntoa(in));     LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] UpstreamInfo->DstPort       %5d.",pid,ri.upDstPort);               LOGUPDATE()
}

inline void S5DebugFacilities( pid_t pid, struct _SS5Facilities fa ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] Facilities->Fixup       %s.",pid,fa.Fixup);           LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] Facilities->Group       %s.",pid,fa.Group);           LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] Facilities->Bandwidth   %12ld.",pid,fa.Bandwidth);    LOGUPDATE()
}

void S5DebugStatistics( pid_t pid ) {
  char logString[256];

  snprintf(logString,256 - 1,"[%u] [DEBU] SS5Statisticsics->V5TC:%lu V4TC:%lu V5NC:%lu V4NC:%lu V5FC:%lu V4FC:%lu V5CC:%lu V4CC:%lu.",pid,
    SS5Statistics.V5Total_Connect,SS5Statistics.V4Total_Connect,SS5Statistics.V5Normal_Connect,SS5Statistics.V4Normal_Connect,
    SS5Statistics.V5Failed_Connect,SS5Statistics.V4Failed_Connect,SS5Statistics.V5Current_Connect,SS5Statistics.V4Current_Connect);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] SS5Statisticsics->V5TB:%lu V4TB:%lu V5NB:%lu V4NB:%lu V5FB:%lu V4FB:%lu V5CB:%lu V4CB:%lu.",pid,
    SS5Statistics.V5Total_Bind,SS5Statistics.V4Total_Bind,SS5Statistics.V5Normal_Bind,SS5Statistics.V4Normal_Bind,
    SS5Statistics.V5Failed_Bind,SS5Statistics.V4Failed_Bind,SS5Statistics.V5Current_Bind,SS5Statistics.V4Current_Bind);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] SS5Statisticsics->V5TU:%lu V5NU:%lu V5FU:%lu V5CU:%lu.",pid,
    SS5Statistics.V5Total_Udp,SS5Statistics.V5Normal_Udp,SS5Statistics.V5Failed_Udp,SS5Statistics.V5Current_Udp);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] SS5Statisticsics->TAF: %lu TAE: %lu TAP: %lu NAF: %lu NAE: %lu NAP: %lu FAF: %lu FAE: %lu FAP: %lu CAF: %lu CAE: %lu CAP: %lu.",pid,
    SS5Statistics.Total_Auth_File,SS5Statistics.Total_Auth_EAP,SS5Statistics.Total_Auth_PAM,
    SS5Statistics.Normal_Auth_File,SS5Statistics.Normal_Auth_EAP,SS5Statistics.Normal_Auth_PAM,
    SS5Statistics.Failed_Auth_File,SS5Statistics.Failed_Auth_EAP,SS5Statistics.Failed_Auth_PAM,
    SS5Statistics.Current_Auth_File,SS5Statistics.Current_Auth_EAP,SS5Statistics.Current_Auth_PAM);    LOGUPDATE()
  snprintf(logString,256 - 1,"[%u] [DEBU] SS5Statisticsics->THF: %lu THL: %lu NHF: %lu NHL: %lu FHF: %lu FHL: %lu CHF: %lu CHL: %lu.",pid,
    SS5Statistics.Total_Author_File,SS5Statistics.Total_Author_Ldap,SS5Statistics.Normal_Author_File,SS5Statistics.Normal_Author_Ldap,
    SS5Statistics.Failed_Author_File,SS5Statistics.Failed_Author_Ldap,SS5Statistics.Current_Author_File,SS5Statistics.Current_Author_Ldap);    LOGUPDATE()
}
