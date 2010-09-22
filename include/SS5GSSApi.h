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

#ifndef SS5GSSAPI_H
#define SS5GSSAPI_H 1


#define GSS_OFFSET_HVER   0
#define GSS_OFFSET_HMTYPE 1
#define GSS_OFFSET_HLEN   2

#define GSS_NO_ENC	  100
#define GSS_ENC_NOINT	  0
#define GSS_ENC_INTEG	  1
#define GSS_ENC_CONFI	  2

#define MAX_GSSTOKEN_SIZE 16192


#define GET_GSSHEADER_LEN(x,y,z)   y=0; for(i=0;i<2;i++) { y += ((unsigned short)x[1-i+z] << ((i)*8)); };
#define SET_GSSHEADER_LEN(x,y,z)   for(i=0;i<2;i++) { x[1-i+z]=(y & (0x00FF << (i*8))) >> (i*8); };

char *MSGGSS[]={
        "0 = AUTHENTICATION",
        "1 = INTEGRITY",
        "2 = CONFIDENTIALITY"};


UINT 
  S5GSSApiSetup( 	struct _SS5ClientInfo *ci );

UINT 
  S5GSSApiEncode(	gss_ctx_id_t ctx, 
			UINT enc, 
			unsigned char *inbuf, 
			unsigned char **oubuf, 
			int *len
);

UINT 
  S5GSSApiDecode(	gss_ctx_id_t ctx, 
			UINT enc, 
			unsigned char *inbuf, 
			unsigned char **oubuf, 
			int *len
);

UINT 
  S5LogGssSCode(	pid_t p, 
			int ma, 
			int mi
);

#endif

