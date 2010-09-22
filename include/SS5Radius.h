/* Socks Server 5
 * Copyright (C) 2003 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

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

#ifndef SS5RADIUS_H
#define SS5RADIUS_H 1

#include <openssl/md5.h>

#define Access_Request      1
#define Access_Accept       2
#define Access_Reject       3
#define Accounting_Request  4
#define Accounting_Response 5

#define ST_Start            1
#define ST_Stop             2
#define ST_Interim_Update   3

#define ATT_User_Name          1
#define ATT_User_Password      2
#define ATT_NAS_Port           5
#define ATT_Framed_IP_Address  8
#define ATT_Framed_Route      22 
#define ATT_Session_Timeout   27
#define ATT_Idle_Timeout      28
#define ATT_Reply_Message     18 
#define ATT_Acct_Status_Type  40
#define ATT_Acct_Session_Id   44
#define ATT_Acct_Input_Octets 42
#define ATT_Acct_Output_Octets 43
#define ATT_Acct_Session_Time 46
#define ATT_Acct_Delay_Time   41
#define ATT_Calling_Station_Id   31
#define ATT_Acct_Interim_Interval   85

#define RADIUS_AUTH_PORT 1812
#define RADIUS_ACCT_PORT 1813

#define OFF_CODE         0
#define OFF_PACKET_ID    1
#define OFF_PACKET_LEN   2
#define OFF_VECTOR       4

#define HEADER_LEN        20
#define VECTOR_LEN        16
#define MAX_PACKET_LEN  4096 
#define RADIUS_TIMEOUT    10

#define GETADDR_R(x,y,z) y=0; for(i=0;i<4;i++) { y += ((ULINT)x[i+z] << (i*8)); };
#define GETXVAL(x,y,z)   y=0; for(i=0;i<4;i++) { y += ((ULINT)x[3-i+z] << (i*8)); };
#define SETPLEN_R(x,y,z) for(i=0;i<2;i++) { x[1-i+z]=(y & (0x00FF << (i*8))) >> (i*8); };
#define SETXVAL_R(x,y,z) for(i=0;i<4;i++) { x[3-i+z]=(y & (0x000000FF << (i*8))) >> (i*8); };

/*
 *  * SS5: Radius configuration parameters
 *   */
struct _S5Radius {
  char IP[16];                      /* Radius server IP               */
  char IPBck[16];                   /* Radius server secondary IP     */
  UINT AuthPort;            /* Radius auth service port       */
  UINT AcctPort;            /* Radius acct service port       */
  char Secret[32];                  /* Radius secret                  */
} S5Radius;


/*
 * Functions for Basic authentication
 */

UINT
  S5RadiusAuth(	struct _SS5ClientInfo *ci,
                 pid_t pid
);

UINT 
  S5RadiusAcct( struct _SS5ClientInfo *ci,
                unsigned long cmd, 
                pid_t pid
);

#endif
