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
    {"prefix", required_argument, NULL, 'w' },
    {"count", required_argument, NULL, 'n' },

    {NULL, 0, NULL, 0}
};


int open_next( Unified2 *unified2, char *prefix )
{
    static int count = 0;
    int string_size = strlen(prefix)+7;
    char *filename = malloc(string_size);

    snprintf(filename, string_size, "%s_%05d", prefix, count);

    Unified2WriteOpenFd(unified2, filename);
    
    free(filename);
    count++;

    return 0;
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
int unified2_loop(char *filename, char *prefix, int count)
{
    int loop_count = count;
    int r = 1;

    Unified2Entry *entry;
    Unified2 *unified2, *write2;
 
    unified2 = Unified2New();
    entry = Unified2EntryNew();
    Unified2ReadOpenFd(unified2, filename);

    while( r != UNIFIED2_EOF )
    {
        loop_count = count;
        write2 = Unified2New();
        open_next(write2, prefix);

        while( loop_count )
        {
            if( loop_count > 0 )
            {
                loop_count--;
            }

            r = Unified2ReadNextEntry(unified2, entry);

            if( r == UNIFIED2_EOF )
            {
                warn("EOF\n");
                break;
            }

            if( r == UNIFIED2_WARN )
            {
                warn("WARNING\n");
                break;
            }

            if( Unified2WriteRecord(write2, entry) == UNIFIED2_ERROR )
            {
                r = UNIFIED2_EOF;
                warn("error writing\n");
            }

            Unified2EntrySparseCleanup(entry);
        }

        Unified2Free(write2);
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
   int ch, i = -1;
    char *filename = NULL;
    char *prefix = NULL;

    /* Get the options */
    while((ch = getopt_long(argc, argv, "r:w:n:", longopts, NULL)) != -1 )
    {
        switch(ch)
        {
            case 'n':
            i = atoi(optarg);
            break;

            case 'r':
            filename = strdup(optarg);
            break;

            case 'w':
            prefix = strdup(optarg);
            break;

            case '?':
            default:
            warn("Usage: %s -n count -r unified2.log\n\n", argv[0]);
            goto DONE;
        }
    }

    /* Check required */
    if( !filename || !prefix )
    {
        warn("Usage: %s -n count -r unified2.log\n\n", argv[0]);
        exit(1);
    }

    /* Loop */
    unified2_loop(filename, prefix, i);

    /* Finish */
    DONE:
    if( filename )
    {
        free(filename);
    }
    return 0;
}
