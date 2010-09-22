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
#include "SS5Mod_authorization.h"
#include "SS5Srv.h"


int main( int argc, char *argv[] )
{

  UINT port=SOCKS5_PORT;
  
  char *p;

  if( (p=(char *)getenv("SS5_SOCKS_PORT")) != NULL  )
    port=(UINT )atoi(p);

  if( argc < 2)
    /* 
     * Display USAGE
     */
    Usage();

  else {
    /*  <CORE> directive  */
    if( !strncmp(argv[1],"list_option",sizeof("list_option") - 1) )
      List_Option( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"write_config",sizeof("write_config") - 1) && argc == 3 )
      Write_Config( argv[2] );

    else if( !strncmp(argv[1],"list_peer",sizeof("list_peer") - 1) )
      List_Peer( "127.0.0.1",port, NULL );

    /*  <ROUTE> directive  */
    else if( !strncmp(argv[1],"list_route",sizeof("list_route") - 1) )
      List_Route( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_route",sizeof("add_route") - 1) && argc == 6 )
      Add_Route( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5] );

    else if( !strncmp(argv[1],"del_route",sizeof("del_route") - 1) && argc == 6 )
      Del_Route( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5] );

    /*  <PROXY> directive */
    else if( !strncmp(argv[1],"list_proxy",sizeof("list_proxy") - 1 ) )
      List_Proxy( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_proxy",sizeof("add_proxy") - 1) && argc == 7 )
      Add_Proxy( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6],PROXY );

    else if( !strncmp(argv[1],"add_noproxy",sizeof("add_noproxy") - 1) && argc == 7 )
      Add_Proxy( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6],NOPROXY );

    else if( !strncmp(argv[1],"del_proxy",sizeof("del_proxy") - 1) && argc == 7 )
      Del_Proxy( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6], PROXY );

    else if( !strncmp(argv[1],"del_noproxy",sizeof("del_noproxy") - 1) && argc == 7 )
      Del_Proxy( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6], NOPROXY );

    /*  <METHOD> directive */
    else if( !strncmp(argv[1],"list_method",sizeof("list_method") - 1) )
      List_Method( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_method",sizeof("add_method") - 1) && argc == 5 )
      Add_Method( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    else if( !strncmp(argv[1],"del_method",sizeof("del_method") - 1) && argc == 5 )
      Del_Method( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    /*  <BANDWIDTH> directive  */
    else if( !strncmp(argv[1],"list_bandwidth",sizeof("list_bandwidth") - 1) )
      List_Bandwidth( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_bandwidth",sizeof("add_bandwidth") - 1) && argc == 5 )
      Add_Bandwidth( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    else if( !strncmp(argv[1],"del_bandwidth",sizeof("del_bandwidth") - 1) && argc == 5 )
      Del_Bandwidth( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    /*  <PERMIT> directive */
    else if( !strncmp(argv[1],"list_autho",sizeof("lisp_autho") - 1) )
      List_Authorization( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_permit",sizeof("add_permit") - 1) && argc == 11 )
      Add_Permit( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],PERMIT );

    else if( !strncmp(argv[1],"del_permit",sizeof("del_permit") - 1) && argc == 11 )
      Del_Permit( "127.0.0.1",port, argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],PERMIT );

    /*  <DUMP> directive  */
    else if( !strncmp(argv[1],"list_dump",sizeof("list_dump") - 1) )
      List_Dump( "127.0.0.1",port, NULL );

    else if( !strncmp(argv[1],"add_dump",sizeof("add_dump") - 1) && argc == 5 )
      Add_Dump( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    else if( !strncmp(argv[1],"del_dump",sizeof("del_dump") - 1) && argc == 5 )
      Del_Dump( "127.0.0.1",port, argv[2],argv[3],argv[4] );

    /*  <VIRTUAL> directive  */
    else if( !strncmp(argv[1],"list_virtual",sizeof("list_virtual") - 1) )
      List_Virtual( "127.0.0.1",port, NULL );

    /*  DISPLAY CACHE  */
    else if( !strncmp(argv[1],"disp_virtualcache",sizeof("disp_virtualcache") - 1) )
      Disp_Virtualcache( "127.0.0.1",port );

    else if( !strncmp(argv[1],"disp_authcache",sizeof("disp_authcache") - 1) )
      Disp_Authcache( "127.0.0.1",port );

    else if( !strncmp(argv[1],"disp_authocache",sizeof("disp_authocache") - 1) )
      Disp_Authocache( "127.0.0.1",port );

    /*  SHOW STATISTICS  */
    else if( !strncmp(argv[1],"show_connect",sizeof("show_connect") - 1) )
      Show_Conn( "127.0.0.1",port );

    else if( !strncmp(argv[1],"show_bind",sizeof("show_bind") - 1) )
      Show_Bind( "127.0.0.1",port );

    else if( !strncmp(argv[1],"show_udp",sizeof("show_udp") - 1) )
      Show_Udp( "127.0.0.1" ,port);

    else if( !strncmp(argv[1],"show_authen",sizeof("show_authen") - 1) )
      Show_Authen( "127.0.0.1",port );

    else if( !strncmp(argv[1],"show_author",sizeof("show_author") - 1) )
      Show_Author( "127.0.0.1",port );

    /*  Display USAGE  */
    else 
      Usage();
  }
  return OK;
}

int Add_Permit( char *addr, UINT port,char *me, char *sa, char *sp, char *da, char *dp, char *fu, char *grp, char *ba, char *ed, UINT f )
{
  int s,ret;

  char buf[480]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"ADD /%s=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",f==PERMIT?"permit":"deny",me,sa,sp,da,dp,fu,grp,ba,ed);
  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Del_Permit( char *addr,UINT port, char *me, char *sa, char *sp, char *da, char *dp, char *fu, char *grp, char *ba, char *ed, UINT f )
{
  int s,ret;

  char buf[480]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"DEL /%s=%1s\n%64s\n%16s\n%64s\n%16s\n%16s\n%256s\n%16s\n%10s\n",f==PERMIT?"permit":"deny",me,sa,sp,da,dp,fu,grp,ba,ed);
  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int Add_Dump( char *addr, UINT port,char *da, char *dp, char *dm )
{
  int s,ret;

  char buf[94]="\0";
  char resp[16]="\0";


  snprintf(buf,sizeof(buf),"ADD /dump=%64s\n%16s\n%1s\n",da,dp,dm);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int Del_Dump( char *addr, UINT port,char *da, char *dp, char *dm )
{
  int s,ret;

  char buf[94]="\0";
  char resp[16]="\0";


  snprintf(buf,sizeof(buf),"DEL /dump=%64s\n%16s\n%1s\n",da,dp,dm);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Add_Proxy( char *addr,UINT port, char *da, char *dp, char *pa, char *pp, char *sv, UINT f )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"ADD /%s=%20s\n%16s\n%16s\n%5s\n%1s\n",f==PROXY?"proxy":"noproxy",da,dp,pa,pp,sv);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Del_Proxy( char *addr, UINT port,char *da, char *dp, char *pa, char *pp, char *sv, UINT f )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"DEL /%s=%20s\n%16s\n%16s\n%5s\n%1s\n",f==PROXY?"proxy":"noproxy",da,dp,pa,pp,sv);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int Add_Route( char *addr, UINT port,char *sa, char *si, char *grp, char *dir )
{
  int s,ret;

  char buf[117]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"ADD /route=%20s\n%16s\n%64s\n%1s\n",sa,si,grp,dir);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Del_Route( char *addr,UINT port, char *sa, char *si, char *grp, char *dir )
{
  int s,ret;

  char buf[117]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"DEL /route=%20s\n%16s\n%64s\n%1s\n",sa,si,grp,dir);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int Add_Method( char *addr, UINT port,char *sa, char *sp, char *me )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"ADD /method=%20s\n%16s\n%1s\n",sa,sp,me);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Del_Method( char *addr,UINT port, char *sa, char *sp, char *me )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"DEL /method=%20s\n%16s\n%1s\n",sa,sp,me);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int Add_Bandwidth( char *addr,UINT port, char *user, char *lncon, char *lband )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";


  snprintf(buf,sizeof(buf),"ADD /bandwidth=\n%64s\n%16s\n%16s\n",user,lncon,lband);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}

int Del_Bandwidth( char *addr,UINT port, char *user, char *lncon, char *lband )
{
  int s,ret;

  char buf[115]="\0";
  char resp[16]="\0";

  snprintf(buf,sizeof(buf),"DEL /bandwidth=\n%64s\n%16s\n%16s\n",user,lncon,lband);

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,sizeof(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else
    perror("Error connecting to server manager: ");

    printf("\n");
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      printf("Result: %2s\n",resp);
    }
    else if( ret == 0 ) {
      fprintf(stderr,"No response from server.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  close(s);
  return OK;
}


int List_Bandwidth( char *addr, UINT port,FILE *ou )
{
  UINT lncon, ncon;
  UINT lband;

  int s,ret,count;

  char *buf="GET /list=BANDWIDTH HTTP/1.1";
  char usr[64],ba[16],co[16],resp[116];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#----------------------------------------------------------------------------------------------------------------------------\n");
  fprintf(ou,"#                                                                     USER           MAXCON        BANDWIDTH       CURRENTCON\n");
  fprintf(ou,"#----------------------------------------------------------------------------------------------------------------------------\n");
  do {
    bzero(resp,116);
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%64s\n%16u\n%16u\n%16u\n",usr,&lncon,&lband,&ncon);
 
      if( lband == 0 ) {
        ba[0]='-';
        ba[1]='\0';
      }
      else
        snprintf(ba,sizeof(ba) - 1,"%u",lband);

      if( lncon == 0 ) {
        co[0]='-';
        co[1]='\0';
      }
      else
        snprintf(co,sizeof(co) - 1,"%u",lncon);

      if( ou == stdout )
        fprintf(ou,"bandwidth %64s %16s %16s %16u\n",usr,co,ba,ncon);
      else
        fprintf(ou,"bandwidth %64s %16s %16s\n",usr,co,ba);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}

int List_Virtual( char *addr, UINT port,FILE *ou )
{
  UINT vid, con;

  int s,ret,count;

  char *buf="GET /list=VIRTUAL HTTP/1.1";
  char real[16],resp[29];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#-----------------------------------------------\n");
  fprintf(ou,"#           VID               REAL    CURRENTCON\n");
  fprintf(ou,"#-----------------------------------------------\n");
  do {
    bzero(resp,29);
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%16s\n%5u\n%5u\n",real,&vid,&con);
      if( ou == stdout )
        fprintf(ou,"virtual   %5u   %16s   %11u\n",vid,real,con);
      else
        fprintf(ou,"virtual   %5u   %16s\n",vid,real);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}


int Disp_Virtualcache( char *addr, UINT port)
{
  UINT vid;

  int s,ret,count;

  time_t ttl,cage;

  char *buf="GET /list=STICKY HTTP/1.1";
  char sa[16],da[16],ttlstr[32],resp[74];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  printf("\n#----------------------------------------------------------------------------------------------------\n");
  printf("#                 SRCIP    VID            DSTIP                        TTL                    TIMENOW\n");
  printf("#----------------------------------------------------------------------------------------------------\n");
  do {
    bzero(resp,74);
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%16s\n%5u\n%16s\n%16ld\n%16ld\n",sa,&vid,da,&ttl,&cage);
      strcpy(ttlstr,ctime(&ttl));
      ttlstr[strlen(ttlstr)-1]='\0';
      printf("       %16s  %5u %16s   %20s   %20s\n",sa,vid,da,ttlstr,ctime(&cage));
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  printf("\n");

  close(s);
  return OK;
}


int List_Authorization( char *addr, UINT port,FILE *ou )
{

  struct in_addr in;
  struct _S5AclNode lnode;

  unsigned short ipA,
                 ipB,
                 ipC,
                 ipD;

  int s,ret,count;

  char *buf="GET /list=AUTHORIZATION HTTP/1.1";
  char me[1]="\0",src[64],dst[64],sfqdn[64],dfqdn[64],srcp[16],dstp[16],resp[553],ba[16];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#----------------------------------------------------------------------------------------------------------------------------------------\n");
  fprintf(ou,"#           METHOD      SRCIP/NET      SRCPORT           DSTIP/NET      DSTPORT    FIXUP                    GROUP    BANDWIDTH    EXPDATE\n");
  fprintf(ou,"#----------------------------------------------------------------------------------------------------------------------------------------\n");

  do {
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%3u\n%16lu\n%64s\n%2u\n%16lu\n%5u\n%5u\n%16lu\n%64s\n%2u\n%16lu\n%5u\n%5u\n%16s\n%256s\n%16lu\n%10s\n%1u\n",
             &lnode.Method,&lnode.SrcAddr,sfqdn,&lnode.SrcMask,&lnode.SrcPort,&lnode.SrcRangeMin,&lnode.SrcRangeMax,
             &lnode.DstAddr,dfqdn,&lnode.DstMask,&lnode.DstPort,&lnode.DstRangeMin,&lnode.DstRangeMax,lnode.Fixup,
             lnode.Group,&lnode.Bandwidth,lnode.ExpDate,&lnode.Type);
      if( sfqdn[0] == '-' ) {
        in.s_addr=lnode.SrcAddr;
        strncpy(src,inet_ntoa(in),sizeof(src));
        sscanf((const char *)src,"%hu.%hu.%hu.%hu",&ipA,&ipB,&ipC,&ipD);
        snprintf(src,sizeof(src),"%hu.%hu.%hu.%hu",ipD,ipC,ipB,ipA);
      }
      else
        strncpy(src,sfqdn,sizeof(src));

      if( dfqdn[0] == '-' ) {
        in.s_addr=lnode.DstAddr;
        strncpy(dst,inet_ntoa(in),sizeof(dst));
        sscanf((const char *)dst,"%hu.%hu.%hu.%hu",&ipA,&ipB,&ipC,&ipD);
        snprintf(dst,sizeof(dst),"%hu.%hu.%hu.%hu",ipD,ipC,ipB,ipA);
      }
      else
        strncpy(dst,dfqdn,sizeof(dst));

      switch(lnode.Method) {
        case NOAUTH:     me[0]='-';     break;
        case USRPWD:     me[0]='u';     break;
        case FAKEPWD:    me[0]='n';     break;
        case S_USER_PWD: me[0]='s';     break;
        case GSSAPI:     me[0]='k';     break;
      }

      if( lnode.Bandwidth == 0 ) {
        ba[0]='-';
        ba[1]='\0';
      }
      else
        snprintf(ba,sizeof(ba) - 1,"%lu",lnode.Bandwidth);

      if( lnode.SrcPort < 65536 )
        snprintf(srcp,sizeof(srcp),"%lu",lnode.SrcPort);
      else
        snprintf(srcp,sizeof(srcp),"%u-%u",lnode.SrcRangeMin,lnode.SrcRangeMax); 

      if( lnode.DstPort < 65536 )
        snprintf(dstp,sizeof(dstp),"%lu",lnode.DstPort);
      else
        snprintf(dstp,sizeof(dstp),"%u-%u",lnode.DstRangeMin,lnode.DstRangeMax); 

      if( lnode.Type == PERMIT ) {
        if( ou == stdout )
          fprintf(ou,"permit %6c %16s/%2u  %11s %16s/%2u  %11s %8s %24s %12s %10s\n",me[0],src,32-lnode.SrcMask,srcp,
             dst,32-lnode.DstMask,dstp,lnode.Fixup,lnode.Group,ba,lnode.ExpDate);
        else
          fprintf(ou,"permit %6c %16s/%u  %11s %16s/%u  %11s %8s %24s %12s %10s\n",me[0],src,32-lnode.SrcMask,srcp,
             dst,32-lnode.DstMask,dstp,lnode.Fixup,lnode.Group,ba,lnode.ExpDate);
      }
      else {
        fprintf(ou,"  deny %6c %16s/%2u  %11s %16s/%2u  %11s %8s %24s %12s %10s\n",me[0],src,32-lnode.SrcMask,srcp,
             dst,32-lnode.DstMask,dstp,lnode.Fixup,lnode.Group,ba,lnode.ExpDate);
      }
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}


int Disp_Authcache( char *addr ,UINT port)
{

  int s,ret,count;

  time_t ttl;

  char *buf="GET /list=AUTHCACHE HTTP/1.1";
  char usr[64],pwd[64],resp[147];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  printf("\n#-------------------------------------------------------------------\n");
  printf("#                   USER         PASSWORD                        TTL\n");
  printf("#-------------------------------------------------------------------\n");

  do {
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%64s\n%64s\n%16ld\n",usr,pwd,&ttl);
      printf("%24s %16s   %16s",usr,pwd,ctime(&ttl));
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  printf("\n");

  close(s);
  return OK;

}

int Disp_Authocache( char *addr, UINT port )
{

  struct _S5AuthoCacheNode lnode;

  int s,ret,count;

  time_t ttl;

  char *buf="GET /list=AUTHOCACHE HTTP/1.1";
  char resp[224+6];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  printf("\n#----------------------------------------------------------------------------------------------------------------\n");
  printf("#                    SRCIP  SRCPORT             DSTIP  DSTPORT              USER     C                        TTL\n");
  printf("#----------------------------------------------------------------------------------------------------------------\n");

  do {
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%64s\n%5u\n%64s\n%5u\n%64s\n%16ld\n%5u\n",lnode.Sa,&lnode.Sp,lnode.Da,&lnode.Dp,lnode.Us,&ttl,&lnode.Flg);
      printf("          %16s   %6u  %16s   %6u  %16s %5u   %24s",lnode.Sa,lnode.Sp,lnode.Da,lnode.Dp,lnode.Us,lnode.Flg,ctime(&ttl));
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  printf("\n");

  close(s);
  return OK;

}

int List_Method( char *addr, UINT port,FILE *ou )
{
  struct in_addr in;
  struct _S5MethodNode lnode;

  int s,ret,count;

  char *buf="GET /list=METHOD HTTP/1.1";
  char me[1]="\0",src[16],srcp[16],resp[57];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#--------------------------------------------\n");
  fprintf(ou,"#              SRCIP/NET      SRCPORT  METHOD\n");
  fprintf(ou,"#--------------------------------------------\n");

  do {
    bzero(resp,sizeof(resp));
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%3u\n%16lu\n%2u\n%16lu\n%5u\n%5u\n",&lnode.Method,&lnode.SrcAddr,&lnode.Mask,&lnode.SrcPort,
                                                    &lnode.SrcRangeMin,&lnode.SrcRangeMax);

      in.s_addr= ntohl(lnode.SrcAddr);
      strncpy(src,inet_ntoa(in),sizeof(src));

      switch(lnode.Method) {
        case NOAUTH:     me[0]='-';     break;
        case USRPWD:     me[0]='u';     break;
        case FAKEPWD:    me[0]='n';     break;
        case S_USER_PWD: me[0]='s';     break;
        case GSSAPI:     me[0]='k';     break;
      }

      if( lnode.SrcPort < 65535 )
        snprintf(srcp,sizeof(srcp),"%lu",lnode.SrcPort);
      else
        snprintf(srcp,sizeof(srcp),"%u-%u",lnode.SrcRangeMin,lnode.SrcRangeMax); 

      if( ou == stdout) 
        fprintf(ou,"auth %16s/%2u  %11s  %6c\n",src,32-lnode.Mask,srcp,me[0]);
      else
        fprintf(ou,"auth %16s/%u  %11s  %6c\n",src,32-lnode.Mask,srcp,me[0]);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}

int List_Dump( char *addr, UINT port,FILE *ou )
{
  struct in_addr in;
  struct _S5DumpNode lnode;

  int s,ret,count;

  char *buf="GET /list=DUMP HTTP/1.1";
  char dm='r',dst[16],dstp[16],resp[51];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#---------------------------------------------\n");
  fprintf(ou,"#              DSTIP/NET      DSTPORT RX/TX/BO\n");
  fprintf(ou,"#---------------------------------------------\n");

  do {
    bzero(resp,sizeof(resp));
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%16lu\n%2u\n%16lu\n%5u\n%5u\n%1u\n",&lnode.DstAddr,&lnode.Mask,&lnode.DstPort,
               &lnode.DstRangeMin,&lnode.DstRangeMax,&lnode.DumpMode);

      in.s_addr=ntohl(lnode.DstAddr);
      strncpy(dst,inet_ntoa(in),sizeof(dst));

      switch(lnode.DumpMode) {
        case 0:     dm='r';     break;
        case 1:     dm='t';     break;
        case 2:     dm='b';     break;
      }

      if( lnode.DstPort < 65536 )
        snprintf(dstp,sizeof(dstp),"%lu",lnode.DstPort);
      else
        snprintf(dstp,sizeof(dstp),"%u-%u",lnode.DstRangeMin,lnode.DstRangeMax); 

      if( ou == stdout )
        fprintf(ou,"dump %16s/%2u  %11s  %7c\n",dst,32-lnode.Mask,dstp,dm);
      else
        fprintf(ou,"dump %16s/%u  %11s  %7c\n",dst,32-lnode.Mask,dstp,dm);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  printf("\n");

  close(s);
  return OK;
}

int List_Proxy( char *addr, UINT port,FILE *ou )
{
  struct in_addr in;
  struct _S5ProxyNode lnode;

  int s,ret,count;

  char *buf="GET /list=PROXY HTTP/1.1";
  char sv[1]="\0",dst[16],dstp[16],pdst[16],resp[80];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#----------------------------------------------------------------------------------\n");
  fprintf(ou,"#                    DSTIP/NET      DSTPORT         PROXYADDR  PROXYPORT   SOCKSVER\n");
  fprintf(ou,"#----------------------------------------------------------------------------------\n");
  do {
    bzero(resp,sizeof(resp));
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%16lu\n%2u\n%16lu\n%5u\n%5u\n%16lu\n%5u\n%3u\n%3u\n",&lnode.DstAddr,&lnode.Mask,&lnode.DstPort,&lnode.DstRangeMin,
             &lnode.DstRangeMax,&lnode.ProxyAddr,&lnode.ProxyPort,&lnode.SocksVer,&lnode.Type);

      in.s_addr=ntohl(lnode.DstAddr);
      strncpy(dst,inet_ntoa(in),sizeof(dst));
      in.s_addr=lnode.ProxyAddr;
      strncpy(pdst,inet_ntoa(in),sizeof(pdst));

      switch(lnode.SocksVer) {
        case SOCKS5_VERSION: sv[0]='5';    break;
        case SOCKS4_VERSION: sv[0]='4';    break;
      }

      if( lnode.DstPort < 65536 )
        snprintf(dstp,sizeof(dstp),"%lu",lnode.DstPort);
      else
        snprintf(dstp,sizeof(dstp),"%u-%u",lnode.DstRangeMin,lnode.DstRangeMax); 

      if( ou == stdout)
        fprintf(ou,"%7s    %16s/%2u  %11s  %16s %10u %10c\n",lnode.Type==PROXY?"proxy":"noproxy",dst,32-lnode.Mask,
             dstp,pdst,lnode.ProxyPort,sv[0]);
      else
        fprintf(ou,"%7s    %16s/%u  %11s  %16s %10u %10c\n",lnode.Type==PROXY?"proxy":"noproxy",dst,32-lnode.Mask,
             dstp,pdst,lnode.ProxyPort,sv[0]);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}

int List_Route( char *addr, UINT port,FILE *ou )
{
  struct in_addr in;
  struct _S5RouteNode lnode;

  int s,ret,count;

  char *buf="GET /list=ROUTE HTTP/1.1";
  char src[16],srcif[16],resp[106];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#----------------------------------------------------------------------------------------------\n");
  fprintf(ou,"#                     IP/NET            BINDIP                               GROUP    DIRECTION\n");
  fprintf(ou,"#----------------------------------------------------------------------------------------------\n");

  do {
    bzero(resp,sizeof(resp));
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%16lu\n%2u\n%16lu\n%64s\n%3u\n",&lnode.SrcAddr,&lnode.Mask,&lnode.SrcIf,lnode.Group,&lnode.sd);

      in.s_addr=ntohl(lnode.SrcAddr);
      strncpy(src,inet_ntoa(in),sizeof(src));
      in.s_addr=lnode.SrcIf;
      strncpy(srcif,inet_ntoa(in),sizeof(srcif));

      fprintf(ou,"route    %16s/%2u  %16s  %34s %12s\n",src,32-lnode.Mask,srcif,lnode.Group,lnode.sd==SRC_ROUTE?"s":"d");
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}


int Show_Conn( char *addr, UINT port)
{
  ULINT v5tc,v4tc,v5nc,v4nc,v5fc,v4fc,v5cc,v4cc;

  int s;

  char *buf="GET /counter=CONNECT HTTP/1.1";
  char resp[32];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Error during server manager comunication (snd): ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Error during server manager comunication (rcv): ");
      fprintf(stderr,"--->Check for SS5_CONSOLE option if set into ss5.conf file.\n");
      return -1;
    }
    sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&v5tc,&v4tc,&v5nc,&v4nc,&v5fc,&v4fc,&v5cc,&v4cc);

    printf("\nCONNECT V4               CONNECT V5\n");
    printf("total   %12lu     total   %12lu\n",v4tc,v5tc);
    printf("normal  %12lu     normal  %12lu\n",v4nc,v5nc);
    printf("failed  %12lu     failed  %12lu\n",v4fc,v5fc);
    printf("current %12lu     current %12lu\n\n",v4cc,v5cc);
  }
  else
    perror("Error connecting to server manager: ");

  close(s);
  return OK;
}

int Show_Bind( char *addr,UINT port )
{
  ULINT v5tb,v4tb,v5nb,v4nb,v5fb,v4fb,v5cb,v4cb;

  int s;

  char *buf="GET /counter=BIND HTTP/1.1";
  char resp[32];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Error during server manager comunication (snd): ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Error during server manager comunication (rcv): ");
      fprintf(stderr,"--->Check for SS5_CONSOLE option if set into ss5.conf file.\n");
      return -1;
    }
    sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&v5tb,&v4tb,&v5nb,&v4nb,&v5fb,&v4fb,&v5cb,&v4cb);

    printf("\nBIND    V4               BIND    V5\n");
    printf("total   %12lu     total   %12lu\n",v4tb,v5tb);
    printf("normal  %12lu     normal  %12lu\n",v4nb,v5nb);
    printf("failed  %12lu     failed  %12lu\n",v4fb,v5fb);
    printf("current %12lu     current %12lu\n\n",v4cb,v5cb);
  }
  else
    perror("Error connecting to server manager: ");

  close(s);
  return OK;
}

int Show_Udp( char *addr,UINT port )
{
  ULINT v5tu,v5nu,v5fu,v5cu;

  int s;

  char *buf="GET /counter=UDP HTTP/1.1";
  char resp[32];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Error during server manager comunication (snd): ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Error during server manager comunication (rcv): ");
      fprintf(stderr,"--->Check for SS5_CONSOLE option if set into ss5.conf file.\n");
      return -1;
    }
    sscanf(resp,"%lu\n%lu\n%lu\n%lu\n",&v5tu,&v5nu,&v5fu,&v5cu);

    printf("\nUDP     V5\n");
    printf("total   %12lu\n",v5tu);
    printf("normal  %12lu\n",v5nu);
    printf("failed  %12lu\n",v5fu);
    printf("current %12lu\n\n",v5cu);
  }
  else
    perror("Error connecting to server manager: ");

  close(s);
  return OK;
}

int Show_Authen( char *addr,UINT port )
{
  ULINT taf,tae,tap,naf,nae,nap,faf,fae,fap,caf,cae,cap;

  int s;

  char *buf="GET /counter=AUTHEN HTTP/1.1";
  char resp[32];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Error during server manager comunication (snd): ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Error during server manager comunication (rcv): ");
      return -1;
    }
    sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n",&taf,&tae,&tap,&naf,&nae,&nap,&faf,&fae,&fap,&caf,&cae,&cap);

    printf("\n       FILE               EAP                      PAM\n"); 
    printf("total   %12lu     total   %12lu     total     %12lu\n",taf,tae,tap);
    printf("normal  %12lu     normal  %12lu     normal    %12lu\n",naf,nae,nap);
    printf("failed  %12lu     failed  %12lu     failed    %12lu\n",faf,fae,fap);
    printf("current %12lu     current %12lu     current   %12lu\n\n",caf,cae,cap);
  }
  else
    perror("Error connecting to server manager: ");

  close(s);
  return OK;
}

int Show_Author( char *addr,UINT port )
{
  ULINT taf,tal,naf,nal,faf,fal,caf,cal;

  int s;

  char *buf="GET /counter=AUTHEN HTTP/1.1";
  char resp[32];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
    if( (recv(s,resp,sizeof(resp),0)) <= 0 ) {
      perror("Receiving error: ");
      return -1;
    }
    sscanf(resp,"%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n%lu\n", &taf,&tal,&naf,&nal,&faf,&fal,&caf,&cal);

    printf("\n       FILE               LDAP\n"); 
    printf("total   %12lu     total   %12lu\n",taf,tal);
    printf("normal  %12lu     normal  %12lu\n",naf,nal);
    printf("failed  %12lu     failed  %12lu\n",faf,fal);
    printf("current %12lu     current %12lu\n\n",caf,cal);
  }
  else
    perror("Connecting error: ");

  close(s);
  return OK;
}


UINT ConnectConsole (char *addr,UINT port ) {

  struct sockaddr_in da_sin;

  int s;

  if ( (s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    return ERR;
  }

  memset((char *)&da_sin, 0, sizeof(struct sockaddr_in));
  da_sin.sin_family      = AF_INET;
  da_sin.sin_port        = htons(port);
  da_sin.sin_addr.s_addr = inet_addr(addr);

  if( connect(s,(struct sockaddr *)&da_sin,sizeof(struct sockaddr_in)) != -1 )
    return s;
  else
    return ERR;

} 

int Write_Config( char *f )
{
  FILE *ou;

  UINT i,l,port=SOCKS5_PORT;

  char *p;

  char logString[256];

  char fn[256];

  if( (p=getenv("SS5_SOCKS_PORT")) != NULL )
    port=atoi(p);

  strncpy(fn,f,sizeof(fn) - 1);
  STRSCAT(fn,".conf");

 /*
  * Open local config file for update
  */
  if( (ou = fopen(fn,"w")) == NULL ) {
    ERRNO(0)

    return ERR;
  }

  fprintf(ou,"#\n"); 
  fprintf(ou,"# %s\n",SS5_VERSION);
  fprintf(ou,"# %s\n",SS5_COPYRIGHT);
  fprintf(ou,"#\n"); 
  fprintf(ou,"# (Configuration file generated by ss5srv tool)\n"); 
  fprintf(ou,"#\n"); 

  List_Option        ("127.0.0.1",port, ou );
  List_Method        ("127.0.0.1",port, ou );
  List_Authorization ("127.0.0.1",port, ou );
  List_Proxy         ("127.0.0.1",port, ou );
  List_Dump          ("127.0.0.1",port, ou );
  List_Virtual       ("127.0.0.1",port, ou );
  List_Bandwidth     ("127.0.0.1",port, ou );

  fclose(ou);

  strncpy(fn,f,sizeof(fn) - 1);
  STRSCAT(fn,".ha");

 /*
  * Open local ha file for update
  */
  if( (ou = fopen(fn,"w")) == NULL ) {
    ERRNO(0)

    return ERR;
  }

  fprintf(ou,"#\n"); 
  fprintf(ou,"# %s\n",SS5_VERSION);
  fprintf(ou,"# %s\n",SS5_COPYRIGHT);
  fprintf(ou,"#\n"); 
  fprintf(ou,"# (Configuration file generated by ss5srv tool)\n"); 
  fprintf(ou,"#\n"); 

  List_Route         ("127.0.0.1",port, ou );
  List_Peer          ("127.0.0.1",port, ou );

  fclose(ou);

  return OK;
}


int List_Option( char *addr, UINT port, FILE *ou )
{
  int s,ret,count;

  char *buf="GET /list=OPTION HTTP/1.1";
  char option[32],value[64],resp[130];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#-------------------------------------------------------------------\n");
  fprintf(ou,"#                             OPTION                           VALUE\n");
  fprintf(ou,"#-------------------------------------------------------------------\n");
  do {
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      sscanf(resp,"%64s\n%64s\n",option,value);
      fprintf(ou,"set %32s",option);
      if( value[0] != '0' )
        fprintf(ou,"%32s\n",value);
      else
        fprintf(ou,"\n");
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}

int List_Peer( char *addr, UINT port, FILE *ou )
{
  int s,ret,count;

  char *buf="GET /list=PEER HTTP/1.1";
  char resp[17];

  if( (s = ConnectConsole( addr, port )) != ERR ) {

    if( send(s,buf,strlen(buf),SS5_SEND_OPT) == -1) {
      perror("Sending error: ");
      return -1;
    }
  }
  else {
    perror("Error connecting to server manager: ");
    return -1;
  }

  count=0;
  if( ou == NULL )
    ou=stdout;

  fprintf(ou,"\n#--------------------\n");
  fprintf(ou,"#                PEER\n");
  fprintf(ou,"#--------------------\n");
  do {
    ret=recv(s,resp,sizeof(resp),0);
    if(ret>0) {
      fprintf(ou,"peer %16s\n",resp);
      count++;
    }
    else if( ret == 0 && count == 0) {
      fprintf(stderr,"No data available for this command.\n");
      fprintf(stderr,"--->Check for SS5_SRV option if set into ss5.conf file.\n");
    }
    else if(ret == -1)
      perror("Error during server manager comunication (rcv): ");

  } while(ret);
  fprintf(ou,"\n");

  close(s);
  return OK;
}


void Usage( void )
{
  printf("\n"); 
  printf("[INFO] %s\n",SS5_VERSION);
  printf("[INFO] %s\n",SS5_COPYRIGHT);
  printf("[INFO] Usage incorrect...\n");
  printf("[INFO] Usage: ss5srv\n");
  printf("[INFO]                                                \n");
  printf("[INFO]     [show_connect]      Show connection statistics\n");
  printf("[INFO]     [show_bind]         Show bind statistics\n");
  printf("[INFO]     [show_udp]          Show udp statistics\n");
  printf("[INFO]                                                \n");
  printf("[INFO]     [list_method]       List <auth>      directive\n");
  printf("[INFO]     [list_autho]        List <permit>    directive\n");
  printf("[INFO]     [list_proxy]        List <proxy>     directive\n");
  printf("[INFO]     [list_route]        List <route>     directive\n");
  printf("[INFO]     [list_dump]         List <dump>      directive\n");
  printf("[INFO]     [list_virtual]      List <virtual>   directive\n");
  printf("[INFO]     [list_bandwidth]    List <bandwidth> directive\n");
  printf("[INFO]     [list_option]       List option      directive\n");
  printf("[INFO]                                                \n");
  printf("[INFO]     [disp_authcache]    Display authentication cache content\n");
  printf("[INFO]     [disp_authocache]   Display authorization cache content\n");
  printf("[INFO]     [disp_virtualcache] Display virtual affinity cache content\n");
  printf("[INFO]                                                \n");
  printf("[INFO]     [add_method]        Add <auth> directive\n");
  printf("[INFO]     [del_method]        Del <auth> directive\n");
  printf("[INFO]     [add_permit]        Add <permit> directive\n");
  printf("[INFO]     [del_permit]        Del <permit> directive\n");
  printf("[INFO]     [add_route]         Add <route> directive\n");
  printf("[INFO]     [del_route]         Del <route> directive\n");
  printf("[INFO]     [add_proxy]         Add <proxy> directive\n");
  printf("[INFO]     [add_noproxy]       Add <noproxy> directive\n");
  printf("[INFO]     [del_proxy]         Del <proxy> directive\n");
  printf("[INFO]     [del_noproxy]       Del <noproxy> directive\n");
  printf("[INFO]     [add_dump]          Add <dump> directive\n");
  printf("[INFO]     [del_dump]          Del <dump> directive\n");
  printf("[INFO]     [add_bandwidth]     Add <bandwidth> directive\n");
  printf("[INFO]     [del_bandwidth]     Del <bandwidth> directive\n");
  printf("[INFO]                                                \n");
  printf("[INFO]     [write_config]      Write online config to file\n");
  printf("\n"); 
}
