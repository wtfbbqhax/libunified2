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

#include "unified2.h"

#define RECORD_SEPARATOR "__________________________________________________________________\n"
#define TO_IP(x) x >> 24, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff

/* Function: Unified2PrintPacketData
 *
 * Purpose: Take a data buffer and a pointer and print it in a stylish hex table.
 *
 * Arguements:
 *      uint8_t *
 *      int
 *
 * Returns:
 *      void
 */
void Unified2PrintPacketData(uint8_t *data, int length)
{
    int i, x, j, c;
    int w = 0;

    for( i=0; length > 0; length-=16 )
    {
        c = length >= 16 ? 16 : length;
        printf("%04X  ", w);
        w+=16;

        /* Unified2Print the data in hex */
        for( j=0; j<c; j++ )
        {
            printf("%2.02X ", data[i+j]);
        }

        /* Pad the output with some spaces if we have less than 16 bytes to
         * print */
        for( x = length; x < 16; x++ )
            printf("   ");

        printf(" ");
        /* Unified2Print the data in strings */
        for( j=0; j<c; j++ )
        {
            printf("%c", (isprint(data[i+j]) ? data[i+j] : '.'));
        }
        printf("\n");

        i+=c;
    }
}

/* Function: Unified2PrintPacketHeader
 *
 * Purpose: Unified2Print the fields of a Unified2Packet to stdout
 *
 * Arguements:
 *      Unified2Packet *
 *
 * Returns:
 *      void
 */
void Unified2PrintPacketRecord(Unified2Packet *packet)
{
    printf("Sensor id           %d\n", packet->sensor_id);
    printf("Event id            %d\n", packet->event_id);
    printf("Event second        %d\n", packet->event_second);
    printf("Packet second       %d\n", packet->packet_second);
    printf("Packet microsecond  %d\n", packet->packet_microsecond);
    printf("Packet linktype     %d\n", packet->linktype);
    printf("Packet length       %d\n", packet->packet_length);
}

/* Function: Unified2PrintEventRecord
 *
 * Purpose: Unified2Print the fields of a Unified2Packet to stdout
 *
 * Arguements:
 *      Unified2Packet *
 *
 * Returns:
 *      void
 */
void Unified2PrintEventRecord(Unified2Event *event)
{

    printf("Sensor id           %d\n", event->sensor_id);
    printf("Event id            %d\n", event->event_id);
    printf("Event second        %d\n", event->event_second);
    printf("Event microsecond   %d\n", event->event_microsecond);
    printf("Signature id        %d\n", event->signature_id);
    printf("Generator id        %d\n", event->generator_id);
    printf("Signature rev       %d\n", event->signature_revision);
    printf("Classification id   %d\n", event->classification_id);
    printf("Priority id         %d\n", event->priority_id);
    printf("IP source           %u.%u.%u.%u\n", TO_IP(event->ip_source));
    printf("IP destination      %u.%u.%u.%u\n", TO_IP(event->ip_destination));
    printf("Source port         %d\n", event->sport_itype);
    printf("Desintation port    %d\n", event->dport_icode);
    printf("Protocol            %d\n", event->protocol);
    printf("Packet action       %d\n", event->packet_action);
}

/* Function: Unified2PrintEventv2Record
 *
 * Purpose: Unified2Print the fields of a Unified2Packet to stdout
 *
 * Arguements:
 *      Unified2Packet *
 *
 * Returns:
 *      void
 */
void Unified2PrintEventv2Record(Unified2Event_v2 *event)
{

    printf("Sensor id           %d\n", event->sensor_id);
    printf("Event id            %d\n", event->event_id);
    printf("Event second        %d\n", event->event_second);
    printf("Event microsecond   %d\n", event->event_microsecond);
    printf("Signature id        %d\n", event->signature_id);
    printf("Generator id        %d\n", event->generator_id);
    printf("Signature rev       %d\n", event->signature_revision);
    printf("Classification id   %d\n", event->classification_id);
    printf("Priority id         %d\n", event->priority_id);
    printf("IP source           %u.%u.%u.%u\n", TO_IP(event->ip_source));
    printf("IP destination      %u.%u.%u.%u\n", TO_IP(event->ip_destination));
    printf("Source port         %d\n", event->sport_itype);
    printf("Desintation port    %d\n", event->dport_icode);
    printf("Protocol            %d\n", event->protocol);
    printf("Packet action       %d\n", event->packet_action);
    printf("MPLS Label          %d\n", event->mpls_label);
    printf("Vlan ID             %d\n", event->vlan_id);
    printf("Policy ID           %d\n", event->policy_id);
}

/* Function: Unified2PrintEvent6Record
 *
 * Purpose: Unified2Print the fields of a Unified2Packet to stdout
 *
 * Arguements:
 *      Unified2Packet *
 *
 * Returns:
 *      void
 */
void Unified2PrintEvent6Record(Unified2Event6 *event)
{
    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &event->ip_source, ip_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event->ip_destination, ip_destination, INET6_ADDRSTRLEN);


    printf("Sensor id           %d\n", event->sensor_id);
    printf("Event id            %d\n", event->event_id);
    printf("Event second        %d\n", event->event_second);
    printf("Event microsecond   %d\n", event->event_microsecond);
    printf("Signature id        %d\n", event->signature_id);
    printf("Generator id        %d\n", event->generator_id);
    printf("Signature rev       %d\n", event->signature_revision);
    printf("Classification id   %d\n", event->classification_id);
    printf("Priority id         %d\n", event->priority_id);
    printf("IP source           %s\n", ip_source);
    printf("IP destination      %s\n", ip_destination);
    printf("Source port         %d\n", event->sport_itype);
    printf("Desintation port    %d\n", event->dport_icode);
    printf("Protocol            %d\n", event->protocol);
    printf("Packet action       %d\n", event->packet_action);
}

/* Function: Unified2PrintEvent6Record
 *
 * Purpose: Unified2Print the fields of a Unified2Packet to stdout
 *
 * Arguements:
 *      Unified2Packet *
 *
 * Returns:
 *      void
 */
void Unified2PrintEvent6v2Record(Unified2Event6_v2 *event)
{
    char ip_source[INET6_ADDRSTRLEN+1];
    char ip_destination[INET6_ADDRSTRLEN+1];
    inet_ntop(AF_INET6, &event->ip_source, ip_source, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &event->ip_destination, ip_destination, INET6_ADDRSTRLEN);


    printf("Sensor id           %d\n", event->sensor_id);
    printf("Event id            %d\n", event->event_id);
    printf("Event second        %d\n", event->event_second);
    printf("Event microsecond   %d\n", event->event_microsecond);
    printf("Signature id        %d\n", event->signature_id);
    printf("Generator id        %d\n", event->generator_id);
    printf("Signature rev       %d\n", event->signature_revision);
    printf("Classification id   %d\n", event->classification_id);
    printf("Priority id         %d\n", event->priority_id);
    printf("IP source           %s\n", ip_source);
    printf("IP destination      %s\n", ip_destination);
    printf("Source port         %d\n", event->sport_itype);
    printf("Desintation port    %d\n", event->dport_icode);
    printf("Protocol            %d\n", event->protocol);
    printf("Packet action       %d\n", event->packet_action);
    printf("MPLS Label          %d\n", event->mpls_label);
    printf("Vlan ID             %d\n", event->vlan_id);
    printf("Policy ID           %d\n", event->policy_id);
}
 
/* Function: Unified2PrintRecord
 *
 * Purpose: Given an entry, figure out what it is and display it
 *
 * Arguements:
 *      Unified2Entry *
 *
 * Returns:
 *      void
 */
HRESULT Unified2PrintRecord(Unified2Entry *entry) {
    if( entry == NULL || entry->record == NULL )
    {
        return UNIFIED2_ERROR;
    }

    switch( entry->record->type )
    {
        case UNIFIED2_IDS_EVENT:
        printf("\n__ Event __________________________________________________________\n");
        Unified2PrintEventRecord(entry->event);
        break;

        case UNIFIED2_IDS_EVENT_V2:
        printf("\n__ Event v2 _______________________________________________________\n");
        Unified2PrintEventv2Record(entry->event_v2);
        break;

        case UNIFIED2_IDS_EVENT_IPV6:
        printf("\n__ Event6 _________________________________________________________\n");
        Unified2PrintEvent6Record(entry->event6);
        break;

        case UNIFIED2_IDS_EVENT_IPV6_V2:
        printf("\n__ Event6 v2 ______________________________________________________\n");
        Unified2PrintEvent6v2Record(entry->event6_v2);
        break;

        case UNIFIED2_PACKET:
        printf("\n__ Packet _________________________________________________________\n");
        Unified2PrintPacketRecord(entry->packet);
        printf("\n");
        Unified2PrintPacketData(entry->packet_data, entry->packet->packet_length);
        break;

    }

    return UNIFIED2_OK;
}
