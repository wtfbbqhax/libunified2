/*******************************************************************************
 * Author:  Victor Roemer
 * Contact: vroemer@sourcefire.com
 * Date:    September 4, 2010
 ******************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#ifdef MACOS
extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;
#endif

#include "unified2.h"

#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff

static struct option longopts[] = {
    {"read", required_argument, NULL, 'r' },
    {"count", required_argument, NULL, 'n' },
    {"help", no_argument, NULL, '?' },
    {"version", no_argument, NULL, 'v' },

    {NULL, 0, NULL, 0}
};

struct progam_vars {
    int record_count;
    char *filename;
    char *program_name;
} pv;

/* Function: print_version
 *
 * Purpose: print the version dialog
 *
 * Arguements:
 *      void
 *
 * Returns:
 *      void
 */
void print_version( ) {
    printf("%s\n", unified2_lib_string());
    printf("Report bugs to <%s>\n", unified2_lib_bugreport());
}

/* Function: print_help
 *
 * Purpose: print the help dialog
 *
 * Arguements:
 *      void
 *
 * Returns:
 *      void
 */
void print_help( ) {
    printf(
    "Usage: %s [-?vr:n:] snort-unified2.log\n"
    "Options:\n"
    "\t-r, --read       Specify file to read\n"
    "\t-n, --count      Number of records to print\n"
    "\t-?, --help       This help\n"
    "\t-v, --version    Print version\n\n",
    pv.program_name
    );

    print_version( );
}

/* Function: parse_args
 *
 * Purpose: abstract arguement parsing outside of main
 *
 * Arguements:
 *      int
 *      char **
 *
 * Returns:
 *      int
 */
int parse_args( int argc, char *argv[] ) {
    int argi = 1;
    int ch;

    pv.record_count = -1;
    pv.filename = NULL;
    pv.program_name = argv[0];

    /* Get the options */
    while((ch = getopt_long(argc, argv, "r:n:?v", longopts, NULL)) != -1 ) {
        argi++;
        switch(ch) {
            case 'n':
            pv.record_count = atoi(optarg);
            break;

            case 'r':
            pv.filename = optarg;
            break;

            case '?':
            default:
            print_help();
            return -1;

            case 'v':
            print_version();
            return -1;
        }
    }

    if( argi < argc && argc > 1 && !pv.filename ) {
        pv.filename = argv[argc-1];
    }

    if( !pv.filename ) {
        print_help();
        return -1;
    }

    return 1;
}

/* Function: print_record_csv
 *
 * Purpose: print a record as a CSV
 *
 * Arguements:
 *      Unified2Entry *
 * 
 * Returns:
 *      void
 */
HRESULT print_record_csv( Unified2Entry *entry ) {
    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];

    Unified2Event *event;
    Unified2Event_v2 *event_v2;
    Unified2Event6 *event6;
    Unified2Event6_v2 *event6_v2;

    if( entry == NULL || entry->record == NULL )
        return UNIFIED2_ERROR;

    switch( entry->record->type ) {
        case UNIFIED2_IDS_EVENT:
        event = entry->event;

        printf("%d,%d,%d,%u.%u.%u.%u,%d,%u.%u.%u.%u,%d,%s,%s\n",
            event->signature_id,
            event->generator_id,
            event->signature_revision,
            TO_IP(event->ip_source),
            event->sport_itype,
            TO_IP(event->ip_destination),
            event->dport_icode,
            (event->protocol == 6   ? "TCP" :
            (event->protocol == 17  ? "UDP" :
            (event->protocol == 1   ? "ICMP" : "IP" ))),
            (event->packet_action == 0x20 ? "Drop" : "Alert")
            );
        break;

        case UNIFIED2_IDS_EVENT_V2:
        event_v2 = entry->event_v2;

        printf("%d,%d,%d,%u.%u.%u.%u,%d,%u.%u.%u.%u,%d,%s,%s\n",
            event_v2->signature_id,
            event_v2->generator_id,
            event_v2->signature_revision,
            TO_IP(event_v2->ip_source),
            event_v2->sport_itype,
            TO_IP(event_v2->ip_destination),
            event_v2->dport_icode,
            (event_v2->protocol == 6   ? "TCP" :
            (event_v2->protocol == 17  ? "UDP" :
            (event_v2->protocol == 1   ? "ICMP" : "IP" ))),
            (event_v2->packet_action == 0x20 ? "Drop" : "Alert")
            );
        break;

        case UNIFIED2_IDS_EVENT_IPV6:
        event6 = entry->event6;

        inet_ntop(AF_INET6, &event6->ip_source, ip_source, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &event6->ip_destination, ip_destination,
        INET6_ADDRSTRLEN);

        printf("%d,%d,%d,%s,%d,%s,%d,%s,%s\n",
            event6->signature_id,
            event6->generator_id,
            event6->signature_revision,
            ip_source,
            event6->sport_itype,
            ip_destination,
            event6->dport_icode,
            (event6->protocol == 6   ? "TCP" :
            (event6->protocol == 17  ? "UDP" :
            (event6->protocol == 1   ? "ICMP" : "IP" ))),
            (event6->packet_action == 0x20 ? "Drop" : "Alert")
            );
        break;


        case UNIFIED2_IDS_EVENT_IPV6_V2:
        event6_v2 = entry->event6_v2;

        inet_ntop(AF_INET6, &event6_v2->ip_source, ip_source, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &event6_v2->ip_destination, ip_destination,
        INET6_ADDRSTRLEN);

        printf("%d,%d,%d,%s,%d,%s,%d,%s,%s\n",
            event6_v2->signature_id,
            event6_v2->generator_id,
            event6_v2->signature_revision,
            ip_source,
            event6_v2->sport_itype,
            ip_destination,
            event6_v2->dport_icode,
            (event6_v2->protocol == 6   ? "TCP" :
            (event6_v2->protocol == 17  ? "UDP" :
            (event6_v2->protocol == 1   ? "ICMP" : "IP" ))),
            (event6_v2->packet_action == 0x20 ? "Drop" : "Alert")
            );
        break;
    }

    return UNIFIED2_OK;
}

/* Function: unified2_loop
 *
 * Purpose: Open the unified2 and print its contents to stdout
 *
 * Arguements:
 *      char *
 *      int
 *
 * Returns:
 *      int
 */
int unified2_loop(char *filename, int loop_count)
{
    int r;

    Unified2Entry *entry;
    Unified2 *unified2;
 
    unified2 = Unified2New();
    entry = Unified2EntryNew();
    Unified2ReadOpenFd(unified2, filename);

    printf("SID,GID,REV,SRC_IP,SRC_PORT,DST_IP,DST_PORT,PROTOCOL,ACTION\n");

    while( loop_count )
    {
        if( loop_count > 0 )
        {
            loop_count--;
        }

        r = Unified2ReadNextEntry(unified2, entry);

        if( r == UNIFIED2_EOF ) {
            break;
        }

        if( r == UNIFIED2_WARN ) {
            break;
        }

        print_record_csv(entry);

        Unified2EntrySparseCleanup(entry);
    }

    Unified2Free(unified2);

    return(1);
}

/* Function: main
 *
 * Purpose: Its main yo!
 *
 * Arguements:
 *      int
 *      char **
 *
 * Returns:
 *      int
 */
int main( int argc, char *argv[] ) {
    if( !parse_args(argc, argv) )
        exit(1);
    else
        unified2_loop(pv.filename, pv.record_count);

    return 0;
}
