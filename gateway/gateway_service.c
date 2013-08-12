/*--------------------+
gateway service
 +-------------------*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>
#include <stdarg.h>

#include <signal.h>
#include <errno.h>

#define recv(a,b,c,d) read(a,b,c)
#define send(a,b,c,d) write(a,b,c)
#define min(X,Y) ((X) < (Y) ? (X) : (Y))

#ifndef uint32
#define uint32 unsigned long int
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "des_test.c"
#include "assign_address.c"
#include "log_request.c"


#define main_return(ret)         \
    {printLog(threadInfo.logfile, "pid %d died . return pid %d return value: (%d)\n",getpid(),pid, ret);\
    exit( 0 );}
//must exit here! in order to kill the whole process in chrome!


///////////  ---  GLOBAL VARIABLES  --- ////////////
///////////------   LOG FILE ------/////////////////
int logNeededbyUser = 0;
char logfileUserDirectory[1024];
FILE *globallogfile;
///////////------   IP POOL ------/////////////////
#define MAX_IP_RANGE 20
#define MAX_SPEC_DOMAIN_RANGE 20
#define MAX_SPEC_IP_PER_DOMAIN 5
#define MAX_DOMAIN_NAME_LENGTH 255
///////////------   configuration ------/////////////////
char IPv6_Interface[1024];
char IPv6_Prefix[1024];
char IPv4_LocalAddress[1024];


typedef struct __SHARE_INFO
{
    int current_allocated_ip_idx;
}SHARE_INFO,*PSHARE_INFO;

PSHARE_INFO shmaddr;
int shmid;



typedef struct __THREAD_INFO
{
    int client_fd;
    FILE *logfile;
    FILE *shortLogfile;
    uint32 auth_ip;
    uint32 netmask;
    uint32 client_ip;
    int connectMethod;
}THREAD_INFO;

int client_thread( THREAD_INFO *pthreadInfo );

int share_mem_initialize(void *shm)
{
    memset(shm, 0, sizeof(SHARE_INFO));
    ((PSHARE_INFO)shm)-> current_allocated_ip_idx = 2;

    return 1;
}


int main(int argc,char **argv)
{

    int pid = 0;

    int n, proxy_port, proxy_fd;
    struct sockaddr_in proxy_addr;
    struct sockaddr_in client_addr;
    THREAD_INFO threadInfo;

    printf("usage: ./gateway_service localIPv4Addr IPv6Interface IPv6Prefix...\n");
    if(argc < 4) {printf("wrong usage\n");exit(0);}
    /* read the arguments */
    strcpy(IPv4_LocalAddress,argv[1]);
    strcpy(IPv6_Interface,argv[2]);
    strcpy(IPv6_Prefix,argv[3]);

    proxy_port = ( argc > 4 ) ?        atoi( argv[4] ) : 8964;
    threadInfo.auth_ip = ( argc > 5 ) ?   inet_addr( argv[5] ) :    0;
    threadInfo.netmask = ( argc > 6 ) ?   inet_addr( argv[6] ) :    0;

    threadInfo.logfile = ( argc > 7 ) ? fopen( argv[7], "a+" ) :  NULL;
    threadInfo.shortLogfile = ( argc > 7 ) ? fopen( argv[7], "a+" ) :  NULL;

    globallogfile = threadInfo.logfile;
    threadInfo.connectMethod = ( argc > 5 ) ? atoi( argv[5] ) :    1;
    threadInfo.auth_ip &= threadInfo.netmask;
    threadInfo.client_ip = 0;

    /* create share memory */
    shmid = shmget(IPC_PRIVATE, sizeof(SHARE_INFO),IPC_CREAT|0600);
    if(shmid < 0)
    {
        printLog(threadInfo.logfile,"[ERROR] get shm ipc_id error\n");
    }

    shmaddr = (PSHARE_INFO) shmat(shmid, NULL, 0 ) ;
    share_mem_initialize(shmaddr);

    /* init encryption seed*/
    key_init();

    /* create a socket */
    proxy_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
    if( proxy_fd < 0 ){
        main_return( 4 );
    }

    /* bind the proxy on the local port and listen */
    n = 1;
    if( setsockopt( proxy_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &n, sizeof( n ) ) < 0 ){
        main_return( 5 );
    }

    proxy_addr.sin_family      = AF_INET;
    proxy_addr.sin_port        = htons( (unsigned short) proxy_port );
    //proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_addr.s_addr = inet_addr(IPv4_LocalAddress);    

    if( bind( proxy_fd, (struct sockaddr *) &proxy_addr,
              sizeof( proxy_addr ) ) < 0 ){
        printLog(threadInfo.logfile,"bind failed in child\n"); 
        main_return( 6 );
    }

    printLog(threadInfo.logfile,"bind ok in child\n");

    struct sockaddr_in proxy_fd_addr;
    socklen_t proxy_fd_addrlen = sizeof(struct sockaddr);
    if(getsockname(proxy_fd,(struct sockaddr *)&proxy_fd_addr, &proxy_fd_addrlen) == -1){
        printLog(threadInfo.logfile,"getsockname ERROR: %s\n", strerror(errno));
    }else{     
        printLog(threadInfo.logfile,"bind sock port is: %d\n", (int) ntohs(proxy_fd_addr.sin_port));
    }       

    /* fork into background */
    if( ( pid = fork() ) < 0 ){//failed
        printLog(threadInfo.logfile, "fork child failed\n");        
        main_return( 2 );
    }

    if( pid > 0 ){  //if(pid) not correct
        printLog(threadInfo.logfile, "pid %d died . return pid %d return value: (%d)\n",getpid(),pid, 0);
        return( (int) ntohs(proxy_fd_addr.sin_port) );
    } else{ 
        printLog(threadInfo.logfile,"a child is born: %d group: %d\n",getpid(),getpgid(getpid()));
    }
     

    /* create a new session */
    if( setsid() < 0 ){
        main_return( 3 );
    }
    printLog(threadInfo.logfile,"create new session , leader: %d group: %d\n",getpid(),getpgid(getpid()));

    
    /* close all file descriptors */
    for( n = 0; n < 2; n++ ){
        close( n );
    }

    printLog(threadInfo.logfile,"write something in child\n");
 
    if( listen( proxy_fd, 20 ) != 0 ){//failed        
        main_return( 7 );
    }

    while( 1 ){

        socklen_t addrlen = sizeof( client_addr );

        /* wait for inboud connections */
        if( ( threadInfo.client_fd = accept( proxy_fd,
                (struct sockaddr *) &client_addr, &addrlen ) ) < 0 ){
            main_return( 8 );
        }

        threadInfo.client_ip = client_addr.sin_addr.s_addr;

        printLog(threadInfo.logfile, "coming inbound connection from port %d\n", (int) ntohs(client_addr.sin_port));
        /* verify that the client is authorized */
        /* not needed if proxy is on own machine */

        /* fork a child to handle the connection */
        if( ( pid = fork() ) < 0 ){
            close( threadInfo.client_fd );
            printLog(threadInfo.logfile, "(a) fork child failed, continue\n");
            continue;
        }
        
        if( pid > 0 ){ // if(pid) doesn't handle error
            /* in father; wait for the child to terminate */
            close( threadInfo.client_fd );
            printLog(threadInfo.logfile,"pid(%d) start wait!\n",getpid());
            int chld_state;
            int rc_pid = waitpid( pid, &chld_state, 0 );
            //int rc_pid = waitpid( pid, &chld_state, WNOHANG );
            printLog(threadInfo.logfile,"Wait until rc_pid = %d received\n",rc_pid);
            if (rc_pid > 0){
              if (WIFEXITED(chld_state)) {
                printLog(threadInfo.logfile,"Child exited with RC=%d\n",WEXITSTATUS(chld_state));
              }
              if (WIFSIGNALED(chld_state)) {
                printLog(threadInfo.logfile,"Child exited via signal %d\n",WTERMSIG(chld_state));
              }
            }else{/* If no error, continue*/
              if (rc_pid < 0) {
                if (errno == ECHILD) {
                  printLog(threadInfo.logfile,"Child does not exist\n");
                }else {
                  printLog(threadInfo.logfile,"Bad argument passed to waitpid\n");
                  abort();
                }
              }
            }

            printLog(threadInfo.logfile,"pid(%d) long wait!\n",getpid());
            continue;
        }else{
            printLog(threadInfo.logfile,"a child is born: %d group: %d\n",getpid(),getpgid(getpid()));
        }

        /* in child; fork & exit so that father becomes init */

        if( ( pid = fork() ) < 0 ){
            printLog(threadInfo.logfile, "(b) fork child failed\n");
            main_return( 9 );
        }

        if( pid > 0){ //if(pid) is wrong
            main_return( 0 ); //father die, 
        }else{
            printLog(threadInfo.logfile,"a child is born: %d group: %d\n",getpid(),getpgid(getpid()));
        }

        //shmaddr = (PSHARE_INFO)shmat( shmid, NULL, SHM_RDONLY ) ;
        shmaddr = (PSHARE_INFO)shmat( shmid, NULL, NULL ) ;

        main_return( client_thread( &threadInfo ) );
    }

    /* not reached */
    main_return( -1 );
}


#define child_thread_exit(ret)         \
    {printLog(pthreadInfo->logfile, "child_thread_exit: %d\n",ret);\
    shutdown( client_fd, 2 );   \
    shutdown( remote_fd, 2 );   \
    close( client_fd );         \
    close( remote_fd );         \
    return( ret );}

int version_verify(char version)
{
    if(version == 0x10) return 1;
    else return 0;
}

int user_id_verify(char *user_id)
{   
    //TODO
    if(user_id[0]=='-' && user_id[1]=='_' && user_id[2]=='-' && user_id[3]=='d')return 1;
    else return 0;
}

int client_thread( THREAD_INFO *pthreadInfo )
{
    int remote_fd = -1;
    int remote_port;
    int state, c_flag;
    int n, client_fd;
    uint32 client_ip;

    char *str_end, c;
    char *url_host, buffer[1024];
    char *url_port, last_host[256];

    //struct hostent *remote_host;
    struct timeval timeout;

    fd_set rfds;

    client_fd = pthreadInfo->client_fd;
    client_ip = pthreadInfo->client_ip;

    /* fetch the http request headers */
    FD_ZERO( &rfds );
    FD_SET( (unsigned int) client_fd, &rfds );

    timeout.tv_sec  = 10;
    timeout.tv_usec =  0;

    if( select( client_fd + 1, &rfds, NULL, NULL, &timeout ) <= 0 ){
        child_thread_exit( 11 );
    }
    

    //receive request
    if( ( n = recv( client_fd, buffer, 1023, 0 ) ) <= 0 ){
        child_thread_exit( 12 );
    }
    printLog(pthreadInfo->shortLogfile,"--> from extension/plugin(%d):\n",getpid());
    log_request_plain( pthreadInfo->shortLogfile, buffer, n );

    memset( last_host, 0, sizeof( last_host ) );

process_request:

    buffer[n] = '\0';

    /* log the client request */
    if( pthreadInfo->shortLogfile != NULL ){
        printLog(pthreadInfo->shortLogfile,"%d : process_request :\n",getpid());
        log_request( pthreadInfo->shortLogfile, client_ip, buffer, n );
    }

    int USER_DEFINED_IP = 0;
    char bindAddr[INET6_ADDRSTRLEN];
    int bindAddrLength = 0;

    char *pstart = strstr(buffer," Bind/");
    if(pstart != NULL){
        pstart += 6;
        for(;pstart[bindAddrLength]!='\r' && pstart[bindAddrLength]!='\n' && pstart[bindAddrLength]!='\0' && bindAddrLength!=INET6_ADDRSTRLEN+1;bindAddrLength++);
        if(bindAddrLength != INET6_ADDRSTRLEN+1){
            USER_DEFINED_IP = 1;
            memcpy(bindAddr,pstart,bindAddrLength);
            bindAddr[bindAddrLength] = '\0';
            printLog(pthreadInfo->logfile,"bind addr: %s\n",bindAddr);
        }
    }
    //gateway strip the user defined string back
    if(USER_DEFINED_IP == 1){
        int j;
        for(j = -6; j < bindAddrLength; j++)
            pstart[j] = ' ';
    }

    /* obfuscated CONNECT method search */
    c_flag = 0;      
    
    if( strcmp( buffer, "CONNECT ") == 0){
        if( ! pthreadInfo->connectMethod ){
            child_thread_exit( 13 );
        }

        c_flag = 1;
    }

    /* skip the http method (GET, PUT, etc.) */
    url_host = buffer;
    while( *url_host != ' ' ){
        if( ( url_host - buffer ) > 10 ||
             *url_host == '\0' ){
            child_thread_exit( 14 );
        }
        url_host++;
    }

    url_host++;

    /* grab the http server hostname */

    if( ! c_flag ){
        if( strcmp( url_host, "http://") == 0){
            url_host += 7;
        }else if( strcmp( url_host, "https://") == 0){
            url_host += 8;
        }else{
            /* act like a http proxy */
            child_thread_exit( 15 );
        }
    }

    /* resolve the http server hostname */
    /* hostname is stored in url_host */
    str_end = url_host;

    while( *str_end != ':' && *str_end != '/' ){
        if( ( str_end - url_host ) >= 128 ||
             *str_end == '\0' ){
            child_thread_exit( 16 );
        }
        str_end++;
    }

    /* save c to check port number */
    c = *str_end;
    *str_end = '\0';

    /* grab the http server port */
    if( c != ':' ){
        *str_end = '\0';
        remote_port = 80;
        url_port = "80";
    }else{
        url_port = ++str_end;
        while( *str_end != ' ' && *str_end != '/' ){
            if( *str_end < '0' || *str_end > '9' ){
                child_thread_exit( 18 );
            }

            str_end++;

            if( str_end - url_port > 5 ){
                child_thread_exit( 19 );
            }
        }

        c = *str_end;
        *str_end = '\0';
        remote_port = atoi( url_port );
    }

    if( c_flag ){
        if( pthreadInfo->connectMethod == 1 && remote_port != 443 ){
            child_thread_exit( 20 );
        }
    }

    int control_message = 0;
    //deal with IPv6 allocation/release request
    if(strcmp(url_host,"iloveipv6privacyweb.edu") == 0){
        control_message = 1;
        sprintf(url_host,"sound.cs.washington.edu");
        printLog(pthreadInfo->logfile, "Dealing IPv6 request: url_host: %s  request: %s\n",url_host, buffer);
    }
    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;


    memset(&hints, 0, sizeof hints); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // AF_UNSPEC don't care IPv4(AF_INET) or IPv6(AF_INET6)
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

    //printf("remote_port: %d\n",remote_port);
    if ((status = getaddrinfo(url_host, url_port, &hints, &servinfo)) != 0) {
        printLog(pthreadInfo->logfile, "fetch host: %s getaddrinfo error: %s\n",url_host, gai_strerror(status));
        child_thread_exit( 17 );
    }

    //only leave the first here
    freeaddrinfo(servinfo->ai_next); 

    if (servinfo->ai_family == AF_INET){  //IPv4
        if( strcmp( url_host, last_host ) ){
            shutdown( remote_fd, 2 );
            close( remote_fd );

            remote_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

            if( remote_fd < 0 ){
                child_thread_exit( 21 );
            }

            char ipstr[INET_ADDRSTRLEN];
            void *addr;
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(servinfo->ai_family, addr, ipstr, sizeof ipstr);

            if( connect(remote_fd, servinfo->ai_addr, servinfo->ai_addrlen) < 0 ){
                printLog(pthreadInfo->logfile,"connect failed\n");
                child_thread_exit( 50 );
            }
            
            memset( last_host, 0, sizeof( last_host ) );
            strncpy( last_host, url_host, sizeof( last_host ) - 1 );
        }
    }else if(servinfo->ai_family == AF_INET6){//IPv6
        /*choose one IPv6 from IP space, wait to bind socket*/
        /* setup the sockaddr for furthur binding */ 
        struct sockaddr_in6 local_addr6;
        memset(&local_addr6, 0, sizeof(local_addr6));
        local_addr6.sin6_family = AF_INET6;
        local_addr6.sin6_scope_id = 0;

        printLog(pthreadInfo->logfile,"USER_DEFINED_IP = %d\n",USER_DEFINED_IP);
        if(USER_DEFINED_IP == 1){
            inet_pton(AF_INET6,bindAddr,&local_addr6.sin6_addr);
        }else{
            inet_pton(AF_INET6,"::",&local_addr6.sin6_addr);
        }

         /* if not already connected */
        //if( strcmp( url_host, last_host ) ) //different string, not connected
        if(1){
            shutdown( remote_fd, 2 );
            close( remote_fd );

            remote_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
            
            if( remote_fd < 0 ){
                child_thread_exit( 21 );
            }


            if(bind(remote_fd,(struct sockaddr *)&local_addr6,sizeof(local_addr6))<0){                        
                printLog(pthreadInfo->logfile,"bind failed : %s\n",strerror(errno));
                child_thread_exit( 49 );
            }else{
               printLog(pthreadInfo->logfile,"bind success\n");
            }

            char ipstr[INET6_ADDRSTRLEN];
            void *addr;
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)servinfo->ai_addr;
            addr = &(ipv6->sin6_addr);
            inet_ntop(servinfo->ai_family, addr, ipstr, sizeof ipstr);

            if( connect(remote_fd, servinfo->ai_addr, servinfo->ai_addrlen) < 0 ){
                printLog(pthreadInfo->logfile,"connect failed\n");
                child_thread_exit( 50 );
            }

            memset( last_host, 0, sizeof( last_host ) );
            strncpy( last_host, url_host, sizeof( last_host ) - 1 );
        }
    }else{
        printLog(pthreadInfo->logfile,"protocol currently not supported\n");
    }

    *str_end = c;

    if( c_flag ){ //CONNECT request, don't have to pass anything
        /* send HTTP/1.1 200 OK */
        sprintf(buffer,"HTTP/1.0 200 OK\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n%c",'\0');

        printLog(pthreadInfo->shortLogfile,"<-- to extension/plugin(%d):\n",getpid());
        log_request_plain( pthreadInfo->shortLogfile, buffer, strlen(buffer) );

        if( send( client_fd, buffer, strlen(buffer), 0 ) != (int) strlen(buffer) ){
            child_thread_exit( 23 );
        }
    }else{ //pass get/post/etc, could remove something, or maybe not needed?
        int m_len; /* method string length + 1 */
        /* remove "http://hostname[:port]" & send headers */

        m_len = url_host - 7 - buffer;
        n -= 7 + ( str_end - url_host );
        memcpy( str_end -= m_len, buffer, m_len );

        if(control_message == 1){
            char *po = strstr(str_end,"If-None-Match");
            if(po != NULL){
                po[0] = 'X';po[1] = 'X';po[2] = 'X';po[3] = 'X';
            }
            po = strstr(str_end,"1234567890");
            if(po != NULL){
                po[10] = '1';po[11] = '2';po[12] = '3';po[13] = '4';po[14] = '5';
            }
        }

        printLog(pthreadInfo->shortLogfile,"--> to webserver(%d):\n",getpid());
        log_request_plain( pthreadInfo->shortLogfile, str_end, n );
        if( send( remote_fd, str_end, n, 0 ) != n ){
            child_thread_exit( 24 );
        }
    }

    /* tunnel the data between the client and the server */
    printLog(pthreadInfo->logfile,"start to tunnel data\n");

    state = 0;

    while( 1 ){
        FD_ZERO( &rfds );
        FD_SET( (unsigned int) client_fd, &rfds );
        FD_SET( (unsigned int) remote_fd, &rfds );
    
        n = ( client_fd > remote_fd ) ? client_fd : remote_fd;

        if( select( n + 1, &rfds, NULL, NULL, NULL ) < 0 ){
            child_thread_exit( 25 );
        }

        if( FD_ISSET( remote_fd, &rfds ) ){
            if( ( n = recv( remote_fd, buffer, 1023, 0 ) ) <= 0 ){
                child_thread_exit( 26 );
            }

            printLog(pthreadInfo->shortLogfile,"<-- from webserver loop (%d):\n",getpid());
            log_request_plain( pthreadInfo->shortLogfile, buffer, n );
            log_request( pthreadInfo->shortLogfile, client_ip, buffer, n );
            state = 1; /* client finished sending data because it starts recving things */

            if(control_message == 1){
                char *po = strstr(str_end,"ETag");
                if(po != NULL){
                    po[0] = 'X';po[1] = 'X';po[2] = 'X';po[3] = 'X';
                }
                //printf("read ip--\n");
                ((PSHARE_INFO)shmaddr)->current_allocated_ip_idx++;
                //printf("alive ip--\n");
                if(((PSHARE_INFO)shmaddr)->current_allocated_ip_idx == 2000) ((PSHARE_INFO)shmaddr)->current_allocated_ip_idx = 2;
                char uncryptedIP[INET6_ADDRSTRLEN];
                char encryptedIP[INET6_ADDRSTRLEN];
                sprintf(uncryptedIP,"%s%x",IPv6_Prefix,((PSHARE_INFO)shmaddr)->current_allocated_ip_idx);
                encrypt_ipv6(uncryptedIP,encryptedIP,1);

                assign_address(IPv6_Interface,encryptedIP);
                po = strstr(buffer,"\r\n\r\n");
                po = po + 4;
                sprintf(po,";%s;",encryptedIP);
            }

            printLog(pthreadInfo->shortLogfile,"<-- to extension/plugin loop (%d):\n",getpid());
            log_request_plain( pthreadInfo->shortLogfile, buffer, n );
            log_request( pthreadInfo->shortLogfile, client_ip, buffer, n );
            if( send( client_fd, buffer, n, 0 ) != n ){
                child_thread_exit( 27 );
            }

        }

        if( FD_ISSET( client_fd, &rfds ) ){
            if( ( n = recv( client_fd, buffer, 1023, 0 ) ) <= 0 ){
                child_thread_exit( 28 );
            }

            printLog(pthreadInfo->shortLogfile,"--> from extension/plugin loop (%d):\n",getpid());
            log_request_plain( pthreadInfo->shortLogfile, buffer, n );
            log_request( pthreadInfo->shortLogfile, client_ip, buffer, n );

            if( state && ! c_flag ){
                /* new http request */
                goto process_request;
                printLog(pthreadInfo->logfile,"Another Process Request!\n");
            }

            printLog(pthreadInfo->shortLogfile,"--> to webserver loop (%d):\n",getpid());
            log_request_plain( pthreadInfo->shortLogfile, buffer, n );
            if( send( remote_fd, buffer, n, 0 ) != n ){
                child_thread_exit( 29 );
            }
        }
    }


    child_thread_exit( -1 );
}
