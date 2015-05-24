/*******************************************************************************
 * Author:  Victor Roemer
 * Contact: vroemer@sourcefire.com
 * Date:    September 4, 2010
 ******************************************************************************/

#include <stdio.h>
#include <netinet/in.h>

/** UNIFIED2 FILE STRUCTURES **************************************************/

typedef struct _Unified2RecordHeader {
    uint32_t type;
    uint32_t length;
} Unified2RecordHeader;
// 8 bytes

typedef struct _Unified2Event {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint16_t pad;
} Unified2Event;
// 52 bytes

typedef struct _Unified2Event_v2 {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint16_t pad;
    uint32_t mpls_label;
    uint16_t vlan_id;
    uint16_t policy_id;
} Unified2Event_v2;
// 60 bytes

typedef struct _Unified2Event6 {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint16_t pad;
} Unified2Event6;
// 300 bytes

typedef struct _Unified2Event6_v2 {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint16_t pad;
    uint32_t mpls_label;
    uint16_t vlan_id;
    uint16_t policy_id;
} Unified2Event6_v2;
// 308 bytes

typedef struct _Unified2Packet {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
} Unified2Packet;
// 28 bytes

typedef struct _Unified2ExtraHdr {
    uint32_t event_type;
    uint32_t event_length;
} Unified2ExtraHdr;
// 8 bytes

typedef struct _Unified2ExtraData {
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t type;
    uint32_t data_type;
    uint32_t blob_length;
} Unified2ExtraData;
// 24 byes

typedef struct _DataBlob {
    uint32_t length;
    const uint8_t *data;
} DataBlob;
// 8 bytes


/** LOCAL DATA STRUCTURES ******************************************************/

typedef struct _Unified2Entry {
    Unified2RecordHeader    *record;
    Unified2Event           *event;
    Unified2Event_v2        *event_v2;
    Unified2Event6          *event6;
    Unified2Event6_v2       *event6_v2;
    Unified2Packet          *packet;
    void                    *packet_data;
} Unified2Entry;

typedef enum _READ_MODE {
    NONE,
    STREAM,
    DESCRIPTOR,
    MEMORY,
} READ_MODE;

typedef struct _Unified2 {
    READ_MODE mode;
    FILE *fh;
    int fd;
    void *memory;
    int memory_size;
    int memory_offset;
    char *filename;
} Unified2;

typedef enum _RECORD_TYPE {
    UNIFIED2_EVENT = 1,
    UNIFIED2_PACKET = 2,
    UNIFIED2_IDS_EVENT = 7,
    UNIFIED2_EVENT_EXTENDED = 66,
    UNIFIED2_PERFORMANCE = 67,
    UNIFIED2_PORTSCAN = 68,
    UNIFIED2_IDS_EVENT_IPV6 = 72,
    UNIFIED2_IDS_EVENT_MPLS = 99,
    UNIFIED2_IDS_EVENT_IPV6_MPLS = 100,

    UNIFIED2_IDS_EVENT_V2 = 104,
    UNIFIED2_IDS_EVENT_IPV6_V2 = 105,

    UNIFIED2_EXTRA_DATA = 110,
} RECORD_TYPE;

typedef enum HRESULT {
    UNIFIED2_ERROR = -1,
    UNIFIED2_OK,
    UNIFIED2_EOF,
    UNIFIED2_WARN
} HRESULT;



/** PROTOTYPES *****************************************************************/

/* unified2_util.c */
Unified2Entry * Unified2EntryNew();
HRESULT Unified2EntrySparseCleanup();
Unified2 * Unified2New();
HRESULT Unified2ReadOpenFILE(Unified2 *, char *);
HRESULT Unified2ReadOpenFd(Unified2 *, char *);
HRESULT Unified2ReadOpenMemory(Unified2 *, void *, int);
HRESULT Unified2Free(Unified2 *);

int Unified2Eof(Unified2 *);
int Unified2Read(Unified2 *, void *, int);
int _Unified2MemSeek(Unified2 *, int, int);
int Unified2Seek(Unified2 *, int, int);

void warn( char *, ... );

/* unified2_read.c */
Unified2RecordHeader * Unified2ReadRecordHeader(Unified2 *);
Unified2Event * Unified2ReadEvent(Unified2 *);
Unified2Event_v2 * Unified2ReadEvent_v2(Unified2 *);
Unified2Event6 * Unified2ReadEvent6(Unified2 *);
Unified2Event6_v2 * Unified2ReadEvent6_v2(Unified2 *);
Unified2Packet * Unified2ReadPacket(Unified2 *);
void * Unified2ReadPacketData(Unified2 *, Unified2Packet *);

HRESULT Unified2ReadNextEntry(Unified2 *, Unified2Entry *);

/* unified2_write.c */
HRESULT Unified2WriteOpenFd(Unified2 *, char *);
HRESULT Unified2Write(Unified2 *, void *, int);
HRESULT Unified2WriteRecord(Unified2 *, const Unified2Entry *);

/* unified2_config.c */
const char * unified2_lib_version( );
const char * unified2_lib_string( );
const char * unified2_lib_bugreport( );

/* unified2_print.c */
HRESULT Unified2PrintRecord(Unified2Entry *entry);

