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
#include <unistd.h>

#include <arpa/inet.h>

#ifdef LINUX
#include <sys/stat.h>
#elif MACOS
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include "unified2.h"

/* Function: Unified2WriteOpenFd
 *
 * Purpose: Open a file descriptor for writing
 *
 * Arguements:
 *      Unified2 *
 *      char *
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteOpenFd(Unified2 *unified2, char *filename)
{
    if(unified2 == NULL)
    {
        return UNIFIED2_ERROR;
    }

    if(filename == NULL)
    {
        return UNIFIED2_ERROR;
    }


    unified2->fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC, O_RDWR);
    if( unified2->fd == -1 )
    {
        warn("Unified2WriteOpenFd: failed to open the file %s: %s\n", filename,
        strerror(errno));
        return UNIFIED2_ERROR;
    }

    unified2->mode = DESCRIPTOR;
    unified2->filename = strdup(filename);

    return UNIFIED2_OK;
}

/* Function: Unified2Write
 *
 * Purpose: Write to the unified2 file
 *
 * Arguements:
 *      Unified2 *
 *      void *
 *      int
 *
 * Returns:
 *      HRESULT
 */
int Unified2Write(Unified2 *unified2, void *buf, int size)
{
    int bytes_wrote;
    
    if( !unified2->fd || unified2->fd == -1 )
    {
        warn("Unified2Write: invalid file descriptor\n");
        return UNIFIED2_ERROR;
    }

    if( buf == NULL )
    {
        warn("Unfiied2Write: buffer is null\n");
        return UNIFIED2_ERROR;
    }

    if( size <= 0 )
    {
        warn("Unified2Write: invalid size\n");
        return UNIFIED2_ERROR;
    }

    bytes_wrote = write(unified2->fd, buf, size);
    if( bytes_wrote == -1 )
    {
        warn("Unified2Write: failed to write to the file %s: %s\n",
        unified2->filename, strerror(errno));
        return UNIFIED2_ERROR;
    }

    return bytes_wrote;
}

/* Function: Unified2WriteRecordHeader
 *
 * Purpose: Write the record header
 *
 * Arguements:
 *      Unified2 *
 *      Unified2RecordHeader *
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteRecordHeader(Unified2 *unified2, Unified2RecordHeader *record)
{
    int bytes_wrote;

    if( unified2 == NULL )
    {
        warn("Unified2WriteRecord: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }
    
    if( record == NULL )
    {
        warn("Unified2WriteRecord: NULL Unified2Record\n");
        return UNIFIED2_ERROR;
    }

    record->type = htonl(record->type);
    record->length = htonl(record->length);

    bytes_wrote = Unified2Write(unified2, record, sizeof(Unified2RecordHeader));
    if(bytes_wrote != sizeof(Unified2RecordHeader))
    {
        warn("Unified2WriteRecord: failed to write Unified2RecordHeader\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WriteEvent
 *
 * Purpose: Write the event record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Event
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteEvent(Unified2 *unified2, Unified2Event *event)
{
    int bytes_wrote;

    if( unified2 == NULL )
    {
        warn("Unified2WriteEvent: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }
    
    if( event == NULL )
    {
        warn("Unified2WriteEvent: NULL Unified2Event\n");
        return UNIFIED2_ERROR;
    }

    event->sensor_id = htonl(event->sensor_id);
    event->event_id = htonl(event->event_id);
    event->event_second = htonl(event->event_second);
    event->event_microsecond = htonl(event->event_microsecond);
    event->signature_id = htonl(event->signature_id);
    event->generator_id = htonl(event->generator_id);
    event->signature_revision = htonl(event->signature_revision);
    event->classification_id = htonl(event->classification_id);
    event->priority_id = htonl(event->priority_id);
    event->ip_source = htonl(event->ip_source);
    event->ip_destination = htonl(event->ip_destination);
    event->sport_itype = htons(event->sport_itype);
    event->dport_icode = htons(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;

    bytes_wrote = Unified2Write(unified2, event, sizeof(Unified2Event));
    if(bytes_wrote != sizeof(Unified2Event))
    {
        warn("Unified2WriteEvent: failed to write Unified2Event\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WriteEvent_v2
 *
 * Purpose: Write the eventv2 record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Event_v2
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteEvent_v2(Unified2 *unified2, Unified2Event_v2 *event)
{
    int bytes_wrote;

    if( unified2 == NULL )
    {
        warn("Unified2WriteEvent_v2: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }
    
    if( event == NULL )
    {
        warn("Unified2WriteEvent_v2: NULL Unified2Event_v2\n");
        return UNIFIED2_ERROR;
    }

    event->sensor_id = htonl(event->sensor_id);
    event->event_id = htonl(event->event_id);
    event->event_second = htonl(event->event_second);
    event->event_microsecond = htonl(event->event_microsecond);
    event->signature_id = htonl(event->signature_id);
    event->generator_id = htonl(event->generator_id);
    event->signature_revision = htonl(event->signature_revision);
    event->classification_id = htonl(event->classification_id);
    event->priority_id = htonl(event->priority_id);
    event->ip_source = htonl(event->ip_source);
    event->ip_destination = htonl(event->ip_destination);
    event->sport_itype = htons(event->sport_itype);
    event->dport_icode = htons(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;
    event->mpls_label = htonl(event->mpls_label);
    event->vlan_id = htonl(event->vlan_id);
    event->policy_id = htonl(event->policy_id);

    bytes_wrote = Unified2Write(unified2, event, sizeof(Unified2Event_v2));
    if(bytes_wrote != sizeof(Unified2Event_v2))
    {
        warn("Unified2WriteEvent_v2: failed to write Unified2Event_v2\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WriteEvent6
 *
 * Purpose: Write the event6 record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Event6
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteEvent6(Unified2 *unified2, Unified2Event6 *event)
{
    int bytes_wrote;

    if( unified2 == NULL )
    {
        warn("Unified2WriteEvent6: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }
    
    if( event == NULL )
    {
        warn("Unified2WriteEvent6: NULL Unified2Event6\n");
        return UNIFIED2_ERROR;
    }

    event->sensor_id = htonl(event->sensor_id);
    event->event_id = htonl(event->event_id);
    event->event_second = htonl(event->event_second);
    event->event_microsecond = htonl(event->event_microsecond);
    event->signature_id = htonl(event->signature_id);
    event->generator_id = htonl(event->generator_id);
    event->signature_revision = htonl(event->signature_revision);
    event->classification_id = htonl(event->classification_id);
    event->priority_id = htonl(event->priority_id);
    event->sport_itype = htons(event->sport_itype);
    event->dport_icode = htons(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;

    bytes_wrote = Unified2Write(unified2, event, sizeof(Unified2Event6));
    if(bytes_wrote != sizeof(Unified2Event6))
    {
        warn("Unified2WriteEvent6: failed to write Unified2Event6\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WriteEvent6_v2
 *
 * Purpose: Write the event6_v2 record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Event6_v2
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteEvent6_v2(Unified2 *unified2, Unified2Event6_v2 *event)
{
    int bytes_wrote;

    if( unified2 == NULL )
    {
        warn("Unified2WriteEvent6_v2: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }
    
    if( event == NULL )
    {
        warn("Unified2WriteEvent6_v2: NULL Unified2Event6_v2\n");
        return UNIFIED2_ERROR;
    }

    event->sensor_id = htonl(event->sensor_id);
    event->event_id = htonl(event->event_id);
    event->event_second = htonl(event->event_second);
    event->event_microsecond = htonl(event->event_microsecond);
    event->signature_id = htonl(event->signature_id);
    event->generator_id = htonl(event->generator_id);
    event->signature_revision = htonl(event->signature_revision);
    event->classification_id = htonl(event->classification_id);
    event->priority_id = htonl(event->priority_id);
    event->sport_itype = htons(event->sport_itype);
    event->dport_icode = htons(event->dport_icode);
    event->protocol = event->protocol;
    event->packet_action = event->packet_action;
    event->mpls_label = htonl(event->mpls_label);
    event->vlan_id = htonl(event->vlan_id);
    event->policy_id = htonl(event->policy_id);

    bytes_wrote = Unified2Write(unified2, event, sizeof(Unified2Event6_v2));
    if(bytes_wrote != sizeof(Unified2Event6_v2))
    {
        warn("Unified2WriteEvent6_v2: failed to write Unified2Event6_v2\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WritePacket
 *
 * Purpose: Write the packet record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Packet *
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WritePacket(Unified2 *unified2, Unified2Packet *packet) {
    int bytes_wrote;

    if(unified2 == NULL)
    {
        warn("Unified2WritePacket: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }

    if(packet == NULL)
    {
        warn("Unified2WritePacket: NULL Unified2Packet\n");
        return UNIFIED2_ERROR;
    }

    packet->sensor_id = htonl(packet->sensor_id);
    packet->event_id = htonl(packet->event_id);
    packet->event_second = htonl(packet->event_second);
    packet->packet_second = htonl(packet->packet_second);
    packet->packet_microsecond = htonl(packet->packet_microsecond);
    packet->linktype = htonl(packet->linktype);
    packet->packet_length = htonl(packet->packet_length);

    bytes_wrote = Unified2Write(unified2, packet, sizeof(Unified2Packet));
    if(bytes_wrote != sizeof(Unified2Packet))
    {
        warn("Unified2WritePacket: failed to write Unified2Packet\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WritePacketData
 *
 * Purpose: Write the packet record
 *
 * Arguements:
 *      Unified2 *
 *      void *
 *      int
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WritePacketData(Unified2 *unified2, void *packet_data, int packet_length)
{
    int bytes_wrote;

    if(unified2 == NULL)
    {
        warn("Unified2WritePacketData: NULL Unified2\n");
        return UNIFIED2_ERROR;
    }

    if( packet_data == NULL )
    {
        warn("Unified2WritePacketData: no packet data\n");
        return UNIFIED2_ERROR;
    }

    bytes_wrote = Unified2Write(unified2, packet_data, packet_length);
    if(bytes_wrote != packet_length)
    {
        warn("Unified2WritePacketData: failed to write packet data\n");
        return UNIFIED2_ERROR;
    }

    return UNIFIED2_OK;
}

/* Function: Unified2WriteRecord
 *
 * Purpose: Write the packet record
 *
 * Arguements:
 *      Unified2 *
 *      Unified2Entry *
 *
 * Returns:
 *      HRESULT
 */
HRESULT Unified2WriteRecord(Unified2 *unified2, const Unified2Entry *entry)
{
    Unified2Entry *local;

    local = (Unified2Entry *) malloc(sizeof(Unified2Entry));
    memcpy(local, entry, sizeof(Unified2Entry));

    if( unified2->fd == -1 )
    {
        warn("Unified2WriteRecord: Invalid file descriptor\n");
        return UNIFIED2_ERROR;
    }

    switch(entry->record->type)
    {
        case UNIFIED2_IDS_EVENT:
        Unified2WriteRecordHeader(unified2, local->record);
        Unified2WriteEvent(unified2, local->event);
        break;

        case UNIFIED2_IDS_EVENT_V2:
        Unified2WriteRecordHeader(unified2, local->record);
        Unified2WriteEvent_v2(unified2, local->event_v2);
        break;

        case UNIFIED2_IDS_EVENT_IPV6:
        Unified2WriteRecordHeader(unified2, local->record);
        Unified2WriteEvent6(unified2, local->event6);
        break;

        case UNIFIED2_IDS_EVENT_IPV6_V2:
        Unified2WriteRecordHeader(unified2, local->record);
        Unified2WriteEvent6_v2(unified2, local->event6_v2);
        break;

        case UNIFIED2_PACKET:
        /* XXX: Need to save off the packet_length while the value is still in
         * host byte order because the write functions will change them to
         * network byte order. */
        //packet_length = entry->packet->packet_length;
        Unified2WriteRecordHeader(unified2, local->record);
        Unified2WritePacket(unified2, local->packet); 
        Unified2WritePacketData(unified2, local->packet_data, entry->packet->packet_length);
        break;
        default:
        warn("Unknown record type\n");
    }

    return UNIFIED2_OK;
}
