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
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifdef LINUX
#include <sys/stat.h>
#elif MACOS
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include "unified2.h"

/* Function: Unified2EntryNew
 *
 * Purpose: Allocate a new entry
 *
 * Arguements:
 *      void
 *
 *  Returns:
 *      Unified2Entry *
 */
Unified2Entry *Unified2EntryNew()
{
    Unified2Entry *entry;

    entry = (Unified2Entry *)malloc(sizeof(Unified2Entry));
    if(entry == NULL)
    {
        warn("Unified2New: failed to malloc the u2: %s\n", strerror(errno));

        return NULL;
    }
    memset(entry, 0x0, sizeof(Unified2Entry));

    return entry;
}

/* Function: Unifiled2EntrySparseCleanup
 *
 * Purpose: Allocate a new Unified2 structure.
 *
 * Arguements:
 *      void
 *
 * Returns:
 *      Unified2 *
 */
HRESULT Unified2EntrySparseCleanup(Unified2Entry *entry )
{
    if( entry == NULL || entry->record == NULL )
    {
        return UNIFIED2_ERROR;
    }

    switch(entry->record->type)
    {
        case UNIFIED2_IDS_EVENT:
        free(entry->event);
        entry->event = NULL;
        break;

        case UNIFIED2_IDS_EVENT_V2:
        free(entry->event_v2);
        entry->event_v2 = NULL;
        break;

        case UNIFIED2_IDS_EVENT_IPV6:
        free(entry->event6);
        entry->event6 = NULL;
        break;

        case UNIFIED2_IDS_EVENT_IPV6_V2:
        free(entry->event6_v2);
        entry->event6_v2 = NULL;
        break;

        case UNIFIED2_PACKET:
        free(entry->packet);
        free(entry->packet_data);
        entry->packet = NULL;
        entry->packet_data = NULL;
        break;
    }

    free(entry->record);
    entry->record = NULL;

    return UNIFIED2_OK;
}

/* Function: Unifiled2New
 *
 * Purpose: Allocate a new Unified2 structure.
 *
 * Arguements:
 *      void
 *
 * Returns:
 *      Unified2 *
 */
Unified2 * Unified2New()
{
    Unified2 *u2;

    u2 = (Unified2 *)malloc(sizeof(Unified2));
    if(u2 == NULL)
    {
        warn("Unified2New: failed to malloc the u2: %s\n", strerror(errno));

        return NULL;
    }
    memset(u2, 0x0, sizeof(Unified2));

    return u2;
}

/* Function: Unifiled2ReadOpenFILE
 *
 * Purpose: Read a Unified2 file as a FILE Stream.
 *
 * Arguements:
 *      HRESULT
 *
 * Returns:
 *      Unified2 *
 *      char *
 */
HRESULT Unified2ReadOpenFILE(Unified2 *u2, char *filename)
{
    FILE *fh;

    if(u2 == NULL)
    {
        return UNIFIED2_ERROR;
    }

    if(filename == NULL)
    {
        return UNIFIED2_ERROR;
    }

    fh = fopen(filename, "rb");
    if(fh == NULL)
    {
        warn("Unified2ReadOpenFILE: failed to open the file %s: %s\n", 
        filename, strerror(errno));

        return UNIFIED2_ERROR;
    }

    u2->mode = STREAM;
    u2->fh = fh;
    u2->filename = strdup(filename);

    return UNIFIED2_OK;
}

HRESULT Unified2ReadOpenFILE_2(Unified2 *u2, FILE *file)
{
    if(u2 == NULL)
    {
        return UNIFIED2_ERROR;
    }

    if(file == NULL)
    {
        warn("Unified2ReadOpenFILE: failed to open the file %s: %s\n", "stdin", strerror(errno));
        return UNIFIED2_ERROR;
    }

    u2->mode = STREAM;
    u2->fh = file;

    return UNIFIED2_OK;
}
/* Function: Unifiled2ReadOpenFd
 *
 * Purpose: Read a Unified2 file from a file descriptor.
 *
 * Arguements:
 *      HRESULT
 *
 * Returns:
 *      Unified2 *
 *      char *
 */
HRESULT Unified2ReadOpenFd(Unified2 *u2, char *filename)
{
    int fd;

    if(u2 == NULL)
    {
        return UNIFIED2_ERROR;
    }

    if(filename == NULL)
    {
        return UNIFIED2_ERROR;
    }

    fd = open(filename, O_RDONLY);
    if(fd == -1)
    {
        warn("Unified2ReadOpenFd: failed to open the file %s: %s\n", filename,
        strerror(errno));
        return UNIFIED2_ERROR;
    }

    u2->mode = DESCRIPTOR;
    u2->fd = fd;
    u2->filename = strdup(filename);

    return UNIFIED2_OK;
}

/* Function: Unifiled2ReadOpenMemory
 *
 * Purpose: Read a Unified2 file from a memory buffer.
 *
 * Arguements:
 *      HRESULT
 *
 * Returns:
 *      Unified2 *
 *      void *
 *      int
 */
HRESULT Unified2ReadOpenMemory(Unified2 *u2, void *buf, int buf_size)
{
    if(u2 == NULL)
    {
        warn("Unified2ReadOpenMemory: buffer must be larger than 0\n");
        return UNIFIED2_ERROR;
    }

    if(buf_size == 0)
    {
        warn("Unified2ReadOpenMemory: buffer must be larger than 0\n");
        return UNIFIED2_ERROR;
    }

    if(buf == NULL)
    {
        warn("Unified2ReadOpenMemory: buffer can not be null\n");
        return UNIFIED2_ERROR;
    }

    u2->mode = MEMORY;
    u2->memory = buf;
    u2->memory_size = buf_size;
    u2->memory_offset = 0;
    u2->filename = strdup("(memory buffer)");

    return UNIFIED2_OK;
}

/* Function: Unifiled2Free
 *
 * Purpose: Free a Unified2 Structure.
 *
 * Arguements:
 *      HRESULT
 *
 * Returns:
 *      Unified2 *
 */
HRESULT Unified2Free(Unified2 *u2)
{
    int r = UNIFIED2_OK;

    if( u2 != NULL )
    {
        switch( u2->mode )
        {
            case STREAM:
            fclose(u2->fh);
            break;
        
            case DESCRIPTOR:
            close(u2->fd);
            break;

            case MEMORY:
            free(u2->memory);
            break;

            case NONE:
            r = UNIFIED2_ERROR;
            break;
        }

        if(u2->filename)
        {
            free(u2->filename);
        }

        free(u2);
        u2 = NULL;
    }
    else
    {
        r = UNIFIED2_ERROR;
    }

    return r;
}

/* Function: Unifiled2Eof
 *
 * Purpose: Check if the file/memory buffer we are reading has reached eof.
 *
 * Arguements:
 *      int
 *
 * Returns:
 *      Unified2 *
 */
int Unified2Eof(Unified2 *u2) {
    int r; 
    char *buf[4];

    switch( u2->mode )
    {
        case STREAM:
        r = feof(u2->fh);
        //r = fread(buf, 4, 1, u2->fh);
        //if (r == 0)
        //{
        //    r = feof(u2->fh);
        //}
        //else
        //{
        //    r = feof(u2->fh);
        //    fseek(u2->fh, -4, SEEK_CUR);
        //}
        break;

        case DESCRIPTOR:
        r = read(u2->fd, buf, 4);
        if( r == 0 )
        {
            r = 1;
        }
        else
        {
            r = 0;
            lseek(u2->fd, -4, SEEK_CUR);
        }
        break;

        case MEMORY:
        if( u2->memory_offset == u2->memory_size )
        {
            r = 1;
        }
        else
        {
            r = 0;
        }
        break;

        default:
        case NONE:
        r = 1;
    }

    return r;
}

static ssize_t
Read(int fildes, uint8_t * buf, uint32_t nbytes)
{
    ssize_t numread;
    unsigned total = 0;

    do {
        numread = read(fildes, buf+total, nbytes-total);
        if (!numread)
            return 0;
        else if (numread > 0)
            total += numread;
        else if (errno != EINTR && errno != EAGAIN)
            return -1;
    } while (total < nbytes);

    if (total < nbytes)
        return total;

    return total;
}

/* Function: Unifiled2Read
 *
 * Purpose: Read from the unified2 file
 *
 * Arguements:
 *      Unified2 *
 *      void *
 *      int
 *
 * Returns:
 *      int
 */
int Unified2Read(Unified2 *u2, void *buf, int size)
{
    int bytes_read;

    switch( u2->mode )
    {
        case STREAM:
        bytes_read = fread(buf, 1, size, u2->fh);
        break;

        case DESCRIPTOR:
        bytes_read = Read(u2->fd, buf, size);
        break;

        case MEMORY:
        /* First, Get bytes that are readable
         *
         * Then, verify that readable bytes is greater than or equal too the amount
         * requested. 
         *
         * Finally, copy the bytes into the buffer
         */ 
        bytes_read = u2->memory_size-u2->memory_offset; 
        bytes_read = bytes_read >= size ? size : bytes_read;
        memcpy(buf, u2->memory+u2->memory_offset, bytes_read);
        u2->memory_offset += bytes_read;
        break;

        default:
        case NONE:
        bytes_read = 0;
    }

    return bytes_read;

}

/* Function: _Unified2MemSeek
 *
 * Purpose: Fake seek function for a memory buffer
 *
 * Arguements:
 *      Unified2 *
 *      int
 *      int
 *
 * Returns:
 *      int
 */
int _Unified2MemSeek(Unified2 *u2, int offset, int whence) {
    int tmp_offset = u2->memory_offset;

    switch(whence)
    {
        case SEEK_SET:
        tmp_offset = offset;
        break;

        case SEEK_END:
        tmp_offset = u2->memory_size;
        /* fall through */

        case SEEK_CUR:
        tmp_offset += offset;
        break;

        default:
        return -1;
    }

    if(tmp_offset < 0 || tmp_offset > u2->memory_size)
    {
        return -1;
    }

    u2->memory_offset = tmp_offset;

    return 0;
}

/* Function: Unified2Seek
 *
 * Purpose: Seek through the Unified2 file
 *
 * Arguements:
 *      Unified2 *
 *      int
 *      int
 *
 * Returns:
 *      int
 */
int Unified2Seek(Unified2 *u2, int offset, int whence)
{
    int r;

    switch( u2->mode )
    {
        case STREAM:
        r = fseek(u2->fh, offset, whence);
        break;

        case DESCRIPTOR:
        r = lseek(u2->fd, offset, whence);
        break;

        case MEMORY:
        r = _Unified2MemSeek(u2, offset, whence);
        break;

        default:
        case NONE:
        r = -1;
 
    }

    return r;
}

/* Function: warn
 *
 * Purpose: print to stderr
 *
 * Arguements:
 *      char *fmt
 *      ...
 *
 * Returns:
 *      void
 */
void warn(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

