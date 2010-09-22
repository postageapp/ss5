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


int Stat_Err( void );
int Stat_Menu( void );
int Stat_Conn( char *addr );
int Stat_Bind( char *addr );
int Stat_Udp( char *addr );
int Stat_Authen( char *addr );
int Stat_Author( char *addr );

int main( int argc, char *argv[] )
{
  if( argc > 1 ) {
    if( !strncmp(argv[1],"CONNECT",sizeof("CONNECT")) )
      Stat_Conn( "127.0.0.1" );
    else if( !strncmp(argv[1],"BIND",sizeof("BIND")) )
      Stat_Bind( "127.0.0.1" );
    else if( !strncmp(argv[1],"UDP",sizeof("UDP")) )
      Stat_Udp( "127.0.0.1" );
    else if( !strncmp(argv[1],"AUTHEN",sizeof("AUTHEN")) )
      Stat_Authen( "127.0.0.1" );
    else if( !strncmp(argv[1],"AUTHOR",sizeof("AUTHOR")) )
      Stat_Author( "127.0.0.1" );
    else
      Stat_Err();
  }
  else
    Stat_Menu();

  return 0;
}

int Stat_Err( void )
{
    printf("Content-type: text/html\n\n");
    printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
    printf("<body> <hr>");
    printf("<p><b> BAD parameter: </p> <br>");
    printf("</BODY>\n</HTML>");

    return 0;
}

int Stat_Menu( void )
{
    printf("Content-type: text/html\n\n");
    printf("<HTML> <HEAD> <TITLE>SS5 statistics manager menu</TITLE></HEAD>\n");
    printf("<body>");
    printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> Statistics Manager Menu: </p> <hr> <br>");
    printf("<p><LI type=square><b><a href=statmgr.cgi?CONNECT><font size=-1> CONNECT counters </font> </p>");
    printf("<p><LI type=square><b><a href=statmgr.cgi?BIND><font size=-1> BIND counters </font> </p>");
    printf("<p><LI type=square><b><a href=statmgr.cgi?UDP><font size=-1> UDP counters </font> </p>");
    printf("<p><LI type=square><b><a href=statmgr.cgi?AUTHEN><font size=-1> AUTHEN counters </font> </p>");
    printf("<p><LI type=square><b><a href=statmgr.cgi?AUTHOR><font size=-1> AUTHOR counters </font> </p>");
    printf("</BODY>\n</HTML>");
   
    return 0;
}

int Stat_Conn( char *addr )
{
  ULINT v5tc,v4tc,v5nc,v4nc,v5fc,v4fc,v5cc,v4cc;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /counter=CONNECT HTTP/1.1";
  char resp[32];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
  }
  else
    perror("Connecting error: ");

  sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&v5tc,&v4tc,&v5nc,&v4nc,&v5fc,&v4fc,&v5cc,&v4cc);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> CONNECT command counters: </p> <hr> <br>");
  printf("<TABLE  border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>V4</td><td><b>Number</td><td><b>V5</td><td><b>Number</td></tr>\n"); 
  printf("<tr><td>total</td><td>%lu</td><td>total</td><td>%lu</td></tr>",v4tc,v5tc);
  printf("<tr><td>normal</td><td>%lu</td><td>normal</td><td>%lu</td></tr>",v4nc,v5nc);
  printf("<tr><td>failed</td><td>%lu</td><td>failed</td><td>%lu</td></tr>",v4fc,v5fc);
  printf("<tr><td>current</td><td>%lu</td><td>current</td><td>%lu</td></tr>",v4cc,v5cc);

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}

int Stat_Bind( char *addr )
{
  ULINT v5tb,v4tb,v5nb,v4nb,v5fb,v4fb,v5cb,v4cb;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /counter=BIND HTTP/1.1";
  char resp[32];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
  }
  else
    perror("Connecting error: ");

  sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&v5tb,&v4tb,&v5nb,&v4nb,&v5fb,&v4fb,&v5cb,&v4cb);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> BIND command counters: </p> <hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>V4</td><td><b>Number</td><td><b>V5</td><td><b>Number</td></tr>\n"); 
  printf("<tr><td>total</td><td>%lu</td><td>total</td><td>%lu</td></tr>",v4tb,v5tb);
  printf("<tr><td>normal</td><td>%lu</td><td>normal</td><td>%lu</td></tr>",v4nb,v5nb);
  printf("<tr><td>failed</td><td>%lu</td><td>failed</td><td>%lu</td></tr>",v4fb,v5fb);
  printf("<tr><td>current</td><td>%lu</td><td>current</td><td>%lu</td></tr>",v4cb,v5cb);

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}

int Stat_Udp( char *addr )
{
  ULINT v5tu,v5nu,v5fu,v5cu;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /counter=UDP HTTP/1.1";
  char resp[32];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
  }
  else
    perror("Connecting error: ");

  sscanf(resp,"%lu\n%lu\n%lu\n%lu\n",&v5tu,&v5nu,&v5fu,&v5cu);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> UDP command counters: </p> <hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>V5</td><td><b>Number</td></tr>\n"); 
  printf("<tr><td>total</td><td>%lu</td></tr>",v5tu);
  printf("<tr><td>normal</td><td>%lu</td></tr>",v5nu);
  printf("<tr><td>failed</td><td>%lu</td></td></tr>",v5fu);
  printf("<tr><td>current</td><td>%lu</td></tr>",v5cu);

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}

int Stat_Authen( char *addr )
{
  ULINT taf,tae,tap,naf,nae,nap,faf,fae,fap,caf,cae,cap;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /counter=AUTHEN HTTP/1.1";
  char resp[32];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
  }
  else
    perror("Connecting error: ");

  sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&taf,&tae,&tap,&naf,&nae,&nap,&faf,&fae,&fap,&caf,&cae,&cap);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> AUTHENTICATION counters: </p> <hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>File</td><td><b>Number</td><td><b>EAP</td><td><b>Number</td><td><b>PAM</td><td><b>Number</td></tr>\n"); 
  printf("<tr><td>total</td><td>%lu</td><td>total</td><td>%lu</td><td>total</td><td>%lu</td></tr>",taf,tae,tap);
  printf("<tr><td>normal</td><td>%lu</td><td>normal</td><td>%lu</td><td>normal</td><td>%lu</td></tr>",naf,nae,nap);
  printf("<tr><td>failed</td><td>%lu</td><td>failed</td><td>%lu</td><td>failed</td><td>%lu</td></tr>",faf,fae,fap);
  printf("<tr><td>current</td><td>%lu</td><td>current</td><td>%lu</td><td>current</td><td>%lu</td></tr>",caf,cae,cap);

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}

int Stat_Author( char *addr )
{
  ULINT taf,tal,naf,nal,faf,fal,caf,cal;

  struct sockaddr_in da_sin;

  int s;

  char *buf="GET /counter=AUTHEN HTTP/1.1";
  char resp[32];

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return 1;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(1080);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
  }
  else
    perror("Connecting error: ");

  sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n", &taf,&tal,&naf,&nal,&faf,&fal,&caf,&cal);

  printf("Content-type: text/html\n\n");
  printf("<HTML> <HEAD> <TITLE>SS5 statistics manager</TITLE></HEAD>\n");
  printf("<body>");
  printf("<p><img src=/SS5Logo.jpg width=50 height=50 align=left><b> AUTHORIZATION counters: </p> </hr> <br>");
  printf("<TABLE border=1; padding:0 cellpadding=2 cellspacing=2>\n");

  printf("<tr><td><b>File</td><td><b>Number</td><td><b>Ldap</td><td><b>Number</td></tr>\n"); 
  printf("<tr><td>total</td><td>%lu</td><td>total</td><td>%lu</td></tr>",taf,tal);
  printf("<tr><td>normal</td><td>%lu</td><td>normal</td><td>%lu</td></tr>",naf,nal);
  printf("<tr><td>failed</td><td>%lu</td><td>failed</td><td>%lu</td></tr>",faf,fal);
  printf("<tr><td>current</td><td>%lu</td><td>current</td><td>%lu</td></tr>",caf,cal);

  printf("</TABLE>\n");
  printf("</BODY>\n</HTML>");

  return 0;
}
