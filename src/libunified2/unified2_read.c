/*******************************************************************************
 * Author:  Victor Roemer
 * Contact: vroemer@sourcefire.com
 * Date:    September 4, 2010
 *
 * Description:
 *
 * This is based heavily off of u2spewfoo.c as of this writing it didn't (at
 * least my copy of it) didn't support the newer event format denoted by v2
 *
 * Otherwise its the snort spo_unified2.h header stripped to bare bones, and an
 * updated interface, something that is more familiar to my coding style.
 *
 * TODO:
 *
 * Error handling:
 *  custom errno to store errors
 *  custom strerror to return string for the custom errno
 *
 * Write Support:
 *  write to FILE *
 *  write to fd
 *  write to memory
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
#include <unistd.h>

#include <arpa/inet.h>

#ifdef LINUX
#include <sys/stat.h>
#include <fcntl.h>
#elif MACOS
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include "unified2.h"

/* Function: Unifiled2ReadRecordHeader
 *
 * Purpose: Read Unified2RecordHeader structures from a file and convert the
 * goofiness to something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2RecordHeader *
 */
Unified2RecordHeader * Unified2ReadRecordHeader(Unified2 *u2)
{
    Unified2RecordHeader *record;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    record = (Unified2RecordHeader *)malloc(sizeof(Unified2RecordHeader));
    if(record == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, record, sizeof(Unified2RecordHeader));
 
    if(!bytes_read || bytes_read != sizeof(Unified2RecordHeader))
    {
        return NULL;
    }

    record->type = ntohl(record->type);
    record->length = ntohl(record->length);

    return record;
}

/* Function: Unifiled2ReadEvent
 *
 * Purpose: Read Unified2Event structures from a file and convert the goofiness
 * to something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2Event *
 */
Unified2Event * Unified2ReadEvent(Unified2 *u2)
{
    Unified2Event *event;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    event = (Unified2Event *)malloc(sizeof(Unified2Event));
    if(event == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, event, sizeof(Unified2Event));

    if(!bytes_read || bytes_read != sizeof(Unified2Event))
    {
        return NULL;
    }

    /* Change from network to host ordering */
    event->sensor_id = ntohl(event->sensor_id);
    event->event_id = ntohl(event->event_id);
    event->event_second = ntohl(event->event_second);
    event->event_microsecond = ntohl(event->event_microsecond);
    event->signature_id = ntohl(event->signature_id);
    event->generator_id = ntohl(event->generator_id);
    event->signature_revision = ntohl(event->signature_revision);
    event->classification_id = ntohl(event->classification_id);
    event->priority_id = ntohl(event->priority_id);
    event->ip_source = ntohl(event->ip_source);
    event->ip_destination = ntohl(event->ip_destination);
    event->sport_itype = ntohs(event->sport_itype);
    event->dport_icode = ntohs(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;
    event->pad = ntohs(event->pad);

    return event;
}

/* Function: Unifiled2ReadEvent_v2
 *
 * Purpose: Read eventv2 structures from a file and convert the goofiness to
 * something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2Event_v2 *
 */
Unified2Event_v2 * Unified2ReadEvent_v2(Unified2 *u2)
{
    Unified2Event_v2 *event_v2;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    event_v2 = (Unified2Event_v2 *)malloc(sizeof(Unified2Event_v2));
    if(event_v2 == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, event_v2, sizeof(Unified2Event_v2));

    if(!bytes_read || bytes_read != sizeof(Unified2Event_v2))
    {
        return NULL;
    }

    /* Change from network to host ordering */
    event_v2->sensor_id = ntohl(event_v2->sensor_id);
    event_v2->event_id = ntohl(event_v2->event_id);
    event_v2->event_second = ntohl(event_v2->event_second);
    event_v2->event_microsecond = ntohl(event_v2->event_microsecond);
    event_v2->signature_id = ntohl(event_v2->signature_id);
    event_v2->generator_id = ntohl(event_v2->generator_id);
    event_v2->signature_revision = ntohl(event_v2->signature_revision);
    event_v2->classification_id = ntohl(event_v2->classification_id);
    event_v2->priority_id = ntohl(event_v2->priority_id);
    event_v2->ip_source = ntohl(event_v2->ip_source);
    event_v2->ip_destination = ntohl(event_v2->ip_destination);
    event_v2->sport_itype = ntohs(event_v2->sport_itype);
    event_v2->dport_icode = ntohs(event_v2->dport_icode);
    event_v2->protocol = event_v2->protocol;
    event_v2->packet_action = event_v2->packet_action;
    event_v2->pad = ntohs(event_v2->pad);
    event_v2->mpls_label = ntohl(event_v2->mpls_label);
    event_v2->vlan_id = ntohs(event_v2->vlan_id);
    event_v2->policy_id = ntohs(event_v2->policy_id);

    return event_v2;
}

/* Function: Unifiled2ReadEvent6
 *
 * Purpose: Read Unified2Event6 structures from a file and convert the
 * goofiness to something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2Event6 *
 */
Unified2Event6 * Unified2ReadEvent6(Unified2 *u2)
{
    Unified2Event6 *event;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    event = (Unified2Event6 *)malloc(sizeof(Unified2Event6));
    if(event == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, event, sizeof(Unified2Event6));

    if(!bytes_read || bytes_read != sizeof(Unified2Event6))
    {
        return NULL;
    }

    /* Change from network to host ordering */
    event->sensor_id = ntohl(event->sensor_id);
    event->event_id = ntohl(event->event_id);
    event->event_second = ntohl(event->event_second);
    event->event_microsecond = ntohl(event->event_microsecond);
    event->signature_id = ntohl(event->signature_id);
    event->generator_id = ntohl(event->generator_id);
    event->signature_revision = ntohl(event->signature_revision);
    event->classification_id = ntohl(event->classification_id);
    event->priority_id = ntohl(event->priority_id);
    /* event->ip_source;        nothing to do for this*/
    /* event->ip_destination;   nothing to do for this*/
    event->sport_itype = ntohs(event->sport_itype);
    event->dport_icode = ntohs(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;
    event->pad = ntohs(event->pad);

    return event;
}

/* Function: Unifiled2ReadEvent6_v2
 *
 * Purpose: Read Unified2Event6_v2 structures from a file and convert the
 * goofiness to something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2Event6_v2 *
 */
Unified2Event6_v2 * Unified2ReadEvent6_v2(Unified2 *u2)
{
    Unified2Event6_v2 *event_v2;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    event_v2 = (Unified2Event6_v2 *)malloc(sizeof(Unified2Event6_v2));
    if(event_v2 == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, event_v2, sizeof(Unified2Event6_v2));

    if(!bytes_read || bytes_read != sizeof(Unified2Event6_v2))
    {
        return NULL;
    }

    /* Change from network to host ordering */
    event_v2->sensor_id = ntohl(event_v2->sensor_id);
    event_v2->event_id = ntohl(event_v2->event_id);
    event_v2->event_second = ntohl(event_v2->event_second);
    event_v2->event_microsecond = ntohl(event_v2->event_microsecond);
    event_v2->signature_id = ntohl(event_v2->signature_id);
    event_v2->generator_id = ntohl(event_v2->generator_id);
    event_v2->signature_revision = ntohl(event_v2->signature_revision);
    event_v2->classification_id = ntohl(event_v2->classification_id);
    event_v2->priority_id = ntohl(event_v2->priority_id);
    /*event_v2->ip_source = ntohl(event_v2->ip_source); */
    /*event_v2->ip_destination = ntohl(event_v2->ip_destination);*/
    event_v2->sport_itype = ntohs(event_v2->sport_itype);
    event_v2->dport_icode = ntohs(event_v2->dport_icode);
    event_v2->protocol = event_v2->protocol;
    event_v2->packet_action = event_v2->packet_action;
    event_v2->pad = ntohs(event_v2->pad);
    event_v2->mpls_label = ntohl(event_v2->mpls_label);
    event_v2->vlan_id = ntohs(event_v2->vlan_id);
    event_v2->policy_id = ntohs(event_v2->policy_id);

    return event_v2;
}

/* Function: Unifiled2ReadPacket
 *
 * Purpose: Read Unified2Packet structures from a file and convert the
 * goofiness to something more usable.
 *
 * Arguements:
 *      Unifiled2 *
 *
 * Returns:
 *      Unified2Packet *
 */
Unified2Packet * Unified2ReadPacket(Unified2 *u2)
{
    Unified2Packet *packet;
    int bytes_read;

    if(u2 == NULL)
    {
        return NULL;
    }

    packet = (Unified2Packet *)malloc(sizeof(Unified2Packet));
    if(packet == NULL)
    {
        return NULL;
    }

    bytes_read = Unified2Read(u2, packet, sizeof(Unified2Packet));

    if(!bytes_read || bytes_read != sizeof(Unified2Packet))
    {
        return NULL;
    }

    packet->sensor_id = ntohl(packet->sensor_id);
    packet->event_id = ntohl(packet->event_id);
    packet->event_second = ntohl(packet->event_second);
    packet->packet_second = ntohl(packet->packet_second);
    packet->packet_microsecond = ntohl(packet->packet_microsecond);
    packet->linktype = ntohl(packet->linktype);
    packet->packet_length = ntohl(packet->packet_length);

    return packet;
}

/* Function: Unifiled2ReadPacketData
 *
 * Purpose: Read the packet data emediately following the Unified2Packet
 * structure into a buffer.
 *
 * Arguements:
 *      Unifiled2 *
 *      Unified2Packet *
 *
 * Returns:
 *      void *
 *
 * XXX
 *      I've removed the uint8_t packet_data[4] blob from the Unified2Packet
 *      structure so that this will work the way it should
 */
void * Unified2ReadPacketData(Unified2 *u2, Unified2Packet *packet)
{
    int bytes_read;
    void *packet_data;

    if(u2 == NULL)
    {
        return NULL;
    }
    
    if(packet == NULL)
    {
        return NULL;
    }

    if(packet->packet_length == 0)
    {
        return NULL;
    }

    packet_data = (void *)malloc(packet->packet_length);
    bytes_read = Unified2Read(u2, packet_data, packet->packet_length);

    if(!bytes_read || bytes_read != packet->packet_length)
    {
        return NULL;
    }

    return packet_data;
}

/* Function: Unifiled2ReadNextEntry
 *
 * Purpose: Read the next Unified2Entry from the Unified2 data
 *
 * Arguements:
 *      Unifiled2 *
 *      Unified2Entry *
 *
 * Returns:
 *      void *
 */
HRESULT Unified2ReadNextEntry(Unified2 *u2, Unified2Entry *entry)
{
    if( u2 == NULL || entry == NULL )
        return UNIFIED2_ERROR;

    READ_AGAIN:

    /* TODO: need to have the option to poll continuously from a unified2 log,
     * when that happens this will need to be turned off. */
    if( Unified2Eof(u2) )
        return UNIFIED2_EOF;


    entry->record = Unified2ReadRecordHeader(u2);
    if( entry->record == NULL )
    {
        return UNIFIED2_ERROR;
    }

    switch( entry->record->type )
    {
        /* Generic Event */
        case UNIFIED2_IDS_EVENT:
            entry->event = Unified2ReadEvent(u2);
            if( entry->event == NULL )
            {
                return UNIFIED2_ERROR;
            }

            break;

        /* Event with MPLS, VLAN, or Policy ID info */
        case UNIFIED2_IDS_EVENT_V2:
            entry->event_v2 = Unified2ReadEvent_v2(u2);
            if( entry->event_v2 == NULL )
            {
                return UNIFIED2_ERROR;
            }
            break;

        /* IPv6 Event */
        case UNIFIED2_IDS_EVENT_IPV6:
            entry->event6 = Unified2ReadEvent6(u2);
            if( entry->event6 == NULL )
            {
                return UNIFIED2_ERROR;
            }
            break;

        /* IPv6 Event with MPLS, VLAN, or Policy ID info */
        case UNIFIED2_IDS_EVENT_IPV6_V2:
            entry->event6_v2 = Unified2ReadEvent6_v2(u2);
            if( entry->event6_v2 == NULL )
            {
                return UNIFIED2_ERROR;
            }
            break;

        /* Packet Data */
        case UNIFIED2_PACKET:
            entry->packet = Unified2ReadPacket(u2);
            entry->packet_data = Unified2ReadPacketData(u2, entry->packet);
            if( entry->packet == NULL )
            {
                return UNIFIED2_ERROR;
            }
            if( entry->packet_data == NULL )
            {
                return UNIFIED2_WARN;
            }
            break;

        default:
            warn("Unknown record type (%d)! ... skipping.\n", entry->record->type);
            Unified2Seek(u2, entry->record->length, SEEK_CUR);
            goto READ_AGAIN;
    }

    return UNIFIED2_OK;
}
