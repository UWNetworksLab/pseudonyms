int printLog (FILE *stream,const char *format, ...)
{
   if(stream == NULL) return 0;
   va_list arg;
   int done;

   va_start (arg, format);
   done = vfprintf (stream, format, arg);
   va_end (arg);

   fflush(stream);
   return done;
}

void log_request_plain( FILE *logfile,
                  char *headers, int headers_len )
{
    int i = 0; 
    for(;i < headers_len;i++){
       printLog( logfile, "%c",headers[i]);       
    }
    printLog( logfile, "\n");
}

void log_request( FILE *logfile, uint32 client_ip,
                  char *headers, int headers_len )
{
    
    int i;
    time_t t;
    struct tm *lt;
    char hyphen[2];
    char buffer[1024];
    char strbuf[32];
    char *ref, *u_a;

    printLog( logfile, "--------\n");
    return;    

    memcpy( buffer, headers, headers_len + 1 );

    /* search for the Referer: and User-Agent: */
    hyphen[0] = '-';
    hyphen[1] = '\0';

    memset( strbuf, 0, sizeof( strbuf ) );

    sprintf(strbuf, "Referer: ");

    ref = strstr( buffer, strbuf );
    ref = ( ( ref == NULL ) ? hyphen : ref +  9 );

    sprintf(strbuf, "User-Agent: ");

    u_a = strstr( buffer, strbuf );
    u_a = ( ( u_a == NULL ) ? hyphen : u_a + 12 );

    /* replace special characters with ' ' */

    for( i = 0; i < headers_len; i++ ){
        if( buffer[i] < 32 ){
            if( buffer[i] == '\r' && buffer[i + 1] == '\n' )
                buffer[i] = '\0';
            else
                buffer[i] = ' ';
        }
    }

    /* finally print the stuff */

    t = time( NULL );
    lt = localtime( &t );

    lt->tm_year += 1900;
    lt->tm_mon++;

    printLog( logfile, "[%04d-%02d-%02d %02d:%02d:%02d]\0",
             lt->tm_year, lt->tm_mon, lt->tm_mday,
             lt->tm_hour, lt->tm_min, lt->tm_sec );

    printLog( logfile, " %d-%d.%d.%d %c%s%c %c%s%c %c%s%c\r\n\0",
             (int) ( client_ip       ) & 0xFF,
             (int) ( client_ip >>  8 ) & 0xFF,
             (int) ( client_ip >> 16 ) & 0xFF,
             (int) ( client_ip >> 24 ) & 0xFF,
             '"',buffer,'"','"', ref,'"','"', u_a,'"' );
}
