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

    while( loop_count )
    {
        if( loop_count > 0 ) {
            loop_count--;
        }

        r = Unified2ReadNextEntry(unified2, entry);

        if( r == UNIFIED2_EOF ) {
            break;
        }

        if( r == UNIFIED2_WARN ) {
            break;
        }

        Unified2PrintRecord( entry );

        Unified2EntrySparseCleanup(entry);
    }

    Unified2Free(unified2);
    printf("\n");

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
