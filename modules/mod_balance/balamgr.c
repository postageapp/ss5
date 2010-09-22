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


int Bala_Vip( char *addr );
int Bala_Err( void );
int Bala_Menu( void );
int Bala_Vip( char *addr );
int Bala_Sticky( char *addr );

int main( int argc, char *argv[] )
{
  if( argc > 1 ) {
    if( !strncmp(argv[1],"VIP",sizeof("VIP")) )
      Bala_Vip( "127.0.0.1" );
    else if( !strncmp(argv[1],"STICKY",sizeof("STICKY")) )
      Bala_Sticky( "127.0.0.1" );
    else
      Bala_Err();
  }
  else
    Bala_Menu();

  return 0;
}

int Bala_Err( void )
{
    printf("Content-type: text/html\n\n");
    printf("<HTML> <HEAD> <TITLE>SS5 balancing manager</TITLE></HEAD>\n");
    printf("<body>");
    printf("<p><b> BAD parameter: </p> <br>");
    printf("</BODY>\n</HTML>");
   
    return 0;
}

int Bala_Menu( void )
{
    printf("Content-type: text/html\n\n");
    printf("<HTML> <HEAD> <TITLE>SS5 balancing manager menu</TITLE></HEAD>\n");
    printf("<body>");
    printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> MENU: </p> <hr> <br>");
    printf("<p><LI type=square><b><a href=balamgr.cgi?VIP><font size=-1> VIP table  </p>");
    printf("<p><LI type=square><b><a href=balamgr.cgi?STICKY><font size=-1> STICKY table  </p>");
    printf("</BODY>\n</HTML>");

    return 0;
}

int Bala_Vip( char *addr )
{
  ULINT vid,nsess;
  char srcip[16];

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /balancing HTTP/1.1";
  char resp[512];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 balancing manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> VIP table: </p> <hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>Source IP</td><td><b>Virtual ID</td><td><b>Session number</td></tr>\n"); 

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    while( recv(s,resp,512,0) > 0 ) {
      sscanf(resp,"%s\n%lu\n%lu\n",srcip,&vid,&nsess);
      printf("<tr><td>%s</td><td>%lu</td><td>%lu</td></tr>",srcip,vid,nsess);
    }
  }
  else
    perror("Connecting error: ");

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}

int Bala_Sticky( char *addr )
{
  UINT vid;
  char srcip[16],dstip[16];
  time_t  ttl,ct;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /sticky HTTP/1.1";
  char resp[512],cur_time[64];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 balancing manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> VIP table: </p> <hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>Source IP</td><td><b>Virtual ID</td><td><b>Destination IP</td><td>TTL</td><td>Current date</td></tr>\n"); 

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    while( recv(s,resp,512,0) > 0 ) {
      sscanf(resp,"%s\n%u\n%s\n%lu\n%lu\n",srcip,&vid,dstip,&ttl,&ct);
#ifdef SOLARIS
          ctime_r(&ct,cur_time,sizeof(cur_time));
#else
          ctime_r(&ct,cur_time);
#endif
      printf("<tr><td>%s</td><td>%u</td><td>%s</td><td>%s</td><td>%s</td></tr>",srcip,vid,dstip,ctime(&ttl),cur_time);
    }
  }
  else
    perror("Connecting error: ");

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}
