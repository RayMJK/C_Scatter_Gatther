////////////////////////////////////////////////////////////////////////////////
//
//  File           : sg_driver.c
//  Description    : This file contains the driver code to be developed by
//                   the students of the 311 class.  See assignment details
//                   for additional information.
//
//   Author        : Myung Joon Kim
//   Last Modified : 12/11/2020
//

// Include Files

// Include Files
#include <string.h>
#include <stdlib.h> // to use uint64_t

// Project Includes
#include <sg_driver.h>
#include <sg_service.h>
#include <sg_cache.h>

// Defines
#define SG_MAGIC_VALUE (uint32_t)0xfefe
//
// Global Data
FILE *fp;
int sgDriverInitialized = 0; // The flag indicating the driver initialized
SG_Block_ID sgLocalNodeId;   // The local node identifier
SG_SeqNum sgLocalSeqno;      // The local sequence number

typedef struct node_seq_struct
{
    int nodeId;
    int rseq;
} node_seq;

node_seq node_seq_list[100000];
int node_seq_size;

int getRemoteNodeSeq(int nodeId)
{
    for (int i = 0; i < node_seq_size; i++)
    {
        if (node_seq_list[i].nodeId == nodeId)
        {
            return node_seq_list[i].rseq;
        }
    }
}

void setRemoteNodeSeq(int nodeId, int rseq)
{
    for (int i = 0; i < node_seq_size; i++)
    {
        if (node_seq_list[i].nodeId == nodeId)
        {
            node_seq_list[i].rseq = rseq;
        }
    }
    node_seq_list[node_seq_size].nodeId = nodeId;
    node_seq_list[node_seq_size++].rseq = rseq;
}

// Driver file entry

typedef struct file_block_struct
{
    SG_Block_ID blkid;
    SG_Node_ID nid;
} file_block;

typedef struct file_entry_struct
{
    SgFHandle handle;
    int size;
    int off;
    file_block fileBlocks[100];
    struct file_entry_struct *prev;
    struct file_entry_struct *next;
} file_entry;
file_entry *fileEntryHead = NULL, *fileEntryTail;
SgFHandle handleUniqueNumber = 3;

file_entry *createFileHandle()
{
    file_entry *entry = (file_entry *)malloc(sizeof(file_entry));
    bzero(entry, sizeof(file_entry));
    entry->handle = handleUniqueNumber;
    handleUniqueNumber += 1;

    if (fileEntryHead == NULL)
    {
        fileEntryHead = fileEntryTail = entry;
    }
    else
    {
        fileEntryTail->next = entry;
        entry->prev = fileEntryTail;
        fileEntryTail = entry;
    }
    return entry;
}

file_entry *searchFileHandle(SgFHandle fh)
{
    file_entry *finder = fileEntryHead;
    while (finder != NULL)
    {
        if (finder->handle == fh)
        {
            return finder;
        }
        finder = finder->next;
    }
    return NULL;
}

int removeFileHandle(SgFHandle fh)
{
    file_entry *entry = searchFileHandle(fh);
    if (entry == NULL)
    {
        return -1;
    }
    if (entry->prev != NULL)
    {
        entry->prev->next = entry->next;
    }
    if (entry->next != NULL)
    {
        entry->next->prev = entry->prev;
    }
    if (fileEntryHead == entry)
    {
        fileEntryHead = fileEntryHead->next;
    }
    if (fileEntryTail == entry)
    {
        fileEntryTail = fileEntryTail->prev;
    }
    free(entry);
    return 0;
}

int getBlockIndex(file_entry *entry)
{
    return entry->off / SG_BLOCK_SIZE;
}

int createStopPacket(char *output)
{
    char recvPacket[SG_BASE_PACKET_SIZE];
    SG_Packet_Status ret;
    size_t pktlen;
    pktlen = SG_BASE_PACKET_SIZE;
    if ((ret = serialize_sg_packet(sgLocalNodeId,    // Local ID
                                   SG_NODE_UNKNOWN,  // Remote ID
                                   SG_BLOCK_UNKNOWN, // Block ID
                                   SG_STOP_ENDPOINT, // Operation
                                   sgLocalSeqno++,   // Sender sequence number
                                   SG_SEQNO_UNKNOWN, // Receiver sequence number
                                   NULL, output, &pktlen)) != SG_PACKT_OK)
    {
        return (-1);
    }

    if (pktlen != SG_BASE_PACKET_SIZE)
    {
        return (-1);
    }
    return (0);
}

int createReadPacket(file_entry *entry, char *output)
{
    char recvPacket[SG_DATA_PACKET_SIZE];
    size_t pktlen, rpktlen;
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    int index = getBlockIndex(entry);

    pktlen = SG_BASE_PACKET_SIZE;
    if ((ret = serialize_sg_packet(sgLocalNodeId,                                  // Local ID
                                   entry->fileBlocks[index].nid,                   // Remote ID
                                   entry->fileBlocks[index].blkid,                 // Block ID
                                   SG_OBTAIN_BLOCK,                                // Operation
                                   sgLocalSeqno++,                                 // Sender sequence number
                                   getRemoteNodeSeq(entry->fileBlocks[index].nid), // Receiver sequence number
                                   NULL, output, &pktlen)) != SG_PACKT_OK)
    {

        return (-1);
    }
    if (pktlen != SG_BASE_PACKET_SIZE)
    {
        return (-1);
    }
    return (0);
}

int parseReadPacket(char *output, char *data, int rpktlen)
{
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    // Unpack the recieived data
    if ((ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                     &srem, data, output, rpktlen)) != SG_PACKT_OK)
    {
        return (-1);
    }
    return 0;
}

int createWritePacket(file_entry *entry, char *data, size_t len, char *outdata, char *output)
{
    int index = getBlockIndex(entry);
    char buf[SG_BLOCK_SIZE];
    size_t pktlen;
    SG_Packet_Status ret;
    size_t initPacketSize = SG_BASE_PACKET_SIZE;
    size_t recvPacketSize = SG_DATA_PACKET_SIZE;
    char initPacket[initPacketSize];
    char recvPacket[recvPacketSize];

    if (entry->off % SG_BLOCK_SIZE != 0 || entry->off != entry->size)
    {
        int bufIndex = entry->off % SG_BLOCK_SIZE;
        if (createReadPacket(entry, initPacket) == -1)
        {
            return (-1);
        }
        if (sgServicePost(initPacket, &initPacketSize, recvPacket, &recvPacketSize))
        {
            return (-1);
        }

        if (parseReadPacket(recvPacket, buf, recvPacketSize) == -1)
        {
            return (-1);
        }
        memcpy(buf + bufIndex, data, len);
    }
    else
    {
        memset(buf, 0x00, SG_BLOCK_SIZE);
        memcpy(buf, data, len);
    }

    pktlen = SG_DATA_PACKET_SIZE;
    if (entry->off % SG_BLOCK_SIZE != 0 || entry->off != entry->size)
    {
        if ((ret = serialize_sg_packet(sgLocalNodeId,                                  // Local ID
                                       entry->fileBlocks[index].nid,                   // Remote ID
                                       entry->fileBlocks[index].blkid,                 // Block ID
                                       SG_UPDATE_BLOCK,                                // Operation
                                       sgLocalSeqno++,                                 // Sender sequence number
                                       getRemoteNodeSeq(entry->fileBlocks[index].nid), // Receiver sequence number
                                       buf, output, &pktlen)) != SG_PACKT_OK)
        {
            return (-1);
        }
    }
    else
    {
        if ((ret = serialize_sg_packet(sgLocalNodeId,    // Local ID
                                       SG_NODE_UNKNOWN,  // Remote ID
                                       SG_BLOCK_UNKNOWN, // Block ID
                                       SG_CREATE_BLOCK,  // Operation
                                       sgLocalSeqno++,   // Sender sequence number
                                       SG_SEQNO_UNKNOWN, // Receiver sequence number
                                       buf, output, &pktlen)) != SG_PACKT_OK)
        {
            printf("IT's ERROR %d\n", ret);
            return (-1);
        }
    }

    memcpy(outdata, buf, SG_BLOCK_SIZE);
    if (pktlen != (SG_DATA_PACKET_SIZE))
    {
        return (-1);
    }
    return (0);
}

int parseWritePacket(char *output, int rpktlen, SG_Node_ID *rem, SG_Block_ID *blkid)
{
    SG_Node_ID loc;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    char data[SG_BLOCK_SIZE];
    // Unpack the recieived data
    if ((ret = deserialize_sg_packet(&loc, rem, blkid, &op, &sloc,
                                     &srem, data, output, rpktlen)) != SG_PACKT_OK)
    {
        return (-1);
    }
    return 0;
}

// Driver support functions
int sgInitEndpoint(void); // Initialize the endpoint

//
// Fuactions

////////////////////////////////////////////////////////////////////////////////
// These functions are used for reporting log.

// open log file pointer and write first log
// filename : name of log file
// init_msg : first log
void init_message(char *filename, char *init_msg)
{
    fp = fopen(filename, "w");
    fprintf(fp, "\n\n%s\n", init_msg);
}

// write log in log_file(for uint64_t)
// msg : log to write(uint64_t, also compatiable with uint32_t, uint16_t)
void write_message(uint64_t msg)
{
    fprintf(fp, "\n%lx\n", msg);
}

// write packet by "hexademical" in log_file(unsigned char array only)
// msg : packet to write(unsigned char array only)
// size : msg's length
void write_message_upacket(unsigned char *msg, int size)
{
    fprintf(fp, "\n\nu_packet : ");
    for (int i = 0; i < size; i++)
    {
        fprintf(fp, "%x ", msg[i]);
    }
    fprintf(fp, "\n\n");
}

// write packet by "decimal" in log_file(char array only)
// msg : packet to write(char array only)
// size : msg's length
void write_message_packet(char *msg, int size)
{
    fprintf(fp, "\n\npacket : ");
    for (int i = 0; i < size; i++)
    {
        fprintf(fp, "%d ", msg[i]);
    }
    fprintf(fp, "\n\n");
}

// write last log and close log file pointer
// end_msg : last log
void end_message(char *end_msg)
{
    fprintf(fp, "\n%s\n\n", end_msg);
    fclose(fp);
}
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// These functions are for handling each byte and changing type

// get unsigned char from uint64_t at specific position
// origin : uint64_t origin
// pos : specific byte to get uchar(not a bit!), start with number 1
unsigned char get_uchar_uint64_t(uint64_t origin, int pos)
{
    origin = origin >> ((8 - pos) * 8);
    return (unsigned char)(origin % 26);
}

void copy_8bit(char *dst, int8_t val)
{
    memcpy(dst, &val, sizeof(int8_t));
}

void copy_16bit(char *dst, int16_t val)
{
    memcpy(dst, &val, sizeof(int16_t));
}

void copy_32bit(char *dst, int32_t val)
{
    memcpy(dst, &val, sizeof(int32_t));
}

void copy_64bit(char *dst, int64_t val)
{
    memcpy(dst, &val, sizeof(int64_t));
}

int8_t get_8bit(char *dst)
{
    int8_t val;
    memcpy(&val, dst, sizeof(int8_t));
    return val;
}

int16_t get_16bit(char *dst)
{
    int16_t val;
    memcpy(&val, dst, sizeof(int16_t));
    return val;
}

int32_t get_32bit(char *dst)
{
    int32_t val = 0;
    memcpy(&val, dst, sizeof(int32_t));
    return val;
}

int64_t get_64bit(char *dst)
{
    int64_t val;
    memcpy(&val, dst, sizeof(int64_t));
    return val;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgopen
// Description  : Open the file for for reading and writing
//
// Inputs       : path - the path/filename of the file to be read
// Outputs      : file handle if successful test, -1 if failure
SgFHandle sgopen(const char *path)
{

    // First check to see if we have been initialized
    if (!sgDriverInitialized)
    {

        // Call the endpoint initialization
        if (sgInitEndpoint())
        {
            logMessage(LOG_ERROR_LEVEL, "sgopen: Scatter/Gather endpoint initialization failed.");
            return (-1);
        }

        // Set to initialized
        sgDriverInitialized = 1;
    }
    return createFileHandle()->handle;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgread
// Description  : Read data from the file
//
// Inputs       : fh - file handle for the file to read from
//                buf - place to put the data
//                len - the length of the read
// Outputs      : number of bytes read, -1 if failure

int sgread(SgFHandle fh, char *buf, size_t len)
{
    file_entry *entry = searchFileHandle(fh);
    char *reqData;
    if (entry == NULL || entry->size <= entry->off)
    {
        return (-1);
    }
    int index = getBlockIndex(entry);
    char *cacheBlock = getSGDataBlock(entry->fileBlocks[index].nid, entry->fileBlocks[index].blkid);
    if (cacheBlock != NULL)
    {
        reqData = cacheBlock + (entry->off % SG_BLOCK_SIZE);
        memcpy(buf, reqData, len);
        entry->off = entry->off + len;
        return (len);
    }
    size_t initPacketSize = SG_BASE_PACKET_SIZE;
    size_t recvPacketSize = SG_DATA_PACKET_SIZE;
    char initPacket[initPacketSize];
    char recvPacket[recvPacketSize];
    if (createReadPacket(entry, initPacket) == -1)
    {
        return (-1);
    }

    if (sgServicePost(initPacket, &initPacketSize, recvPacket, &recvPacketSize))
    {
        return (-1);
    }
    char data[SG_BLOCK_SIZE];
    if (parseReadPacket(recvPacket, data, recvPacketSize) == -1)
    {
        return (-1);
    }

    reqData = data + (entry->off % SG_BLOCK_SIZE);
    memcpy(buf, reqData, len);

    entry->off = entry->off + len;

    putSGDataBlock(entry->fileBlocks[index].nid, entry->fileBlocks[index].blkid, data);

    return (len);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgwrite
// Description  : write data to the file
//
// Inputs       : fh - file handle for the file to write to
//                buf - pointer to data to write
//                len - the length of the write
// Outputs      : number of bytes written if successful test, -1 if failure

int sgwrite(SgFHandle fh, char *buf, size_t len)
{
    file_entry *entry = searchFileHandle(fh);
    if (entry == NULL)
    {
        return (-1);
    }
    size_t initPacketSize = SG_DATA_PACKET_SIZE;
    size_t recvPacketSize = SG_DATA_PACKET_SIZE;
    char initPacket[initPacketSize];
    char recvPacket[recvPacketSize];
    char outdata[SG_BLOCK_SIZE];
    if (createWritePacket(entry, buf, len, outdata, initPacket) == -1)
    {
        return (-1);
    }

    if (sgServicePost(initPacket, &initPacketSize, recvPacket, &recvPacketSize))
    {
        return (-1);
    }

    SG_Node_ID rem;
    SG_Block_ID blkid;
    if (parseWritePacket(recvPacket, recvPacketSize, &rem, &blkid) == -1)
    {
        return (-1);
    }
    int index = getBlockIndex(entry);
    entry->fileBlocks[index].blkid = blkid;
    entry->fileBlocks[index].nid = rem;
    entry->off = entry->off + len;
    entry->size = entry->size + len;
    putSGDataBlock(blkid, rem, outdata);
    return (len);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgseek
// Description  : Seek to a specific place in the file
//
// Inputs       : fh - the file handle of the file to seek in
//                off - offset within the file to seek to
// Outputs      : new position if successful, -1 if failure

int sgseek(SgFHandle fh, size_t off)
{
    file_entry *entry = searchFileHandle(fh);
    if (entry == NULL)
    {
        return (-1);
    }

    if (entry->off > entry->size)
    {
        return (-1);
    }

    entry->off = off;

    return (off);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgclose
// Description  : Close the file
//
// Inputs       : fh - the file handle of the file to close
// Outputs      : 0 if successful test, -1 if failure

int sgclose(SgFHandle fh)
{
    return removeFileHandle(fh);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgshutdown
// Description  : Shut down the filesystem
//
// Inputs       : none
// Outputs      : 0 if successful test, -1 if failure

int sgshutdown(void)
{
    // Close file handle
    file_entry *finder = fileEntryHead, *tmp;
    while (finder != NULL)
    {
        tmp = finder->next;
        sgclose(finder->handle);
        finder = tmp;
    }

    // Close node
    char initPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
    createStopPacket(initPacket);
    SG_Packet_Status ret;
    size_t pktlen, rpktlen;

    pktlen = rpktlen = SG_BASE_PACKET_SIZE;
    if (sgServicePost(initPacket, &pktlen, recvPacket, &rpktlen))
    {
        logMessage(LOG_ERROR_LEVEL, "sgInitEndpoint: failed packet post");
        return (-1);
    }

    // Log, return successfully
    logMessage(LOG_INFO_LEVEL, "Shut down Scatter/Gather driver.");
    closeSGCache();
    return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : serialize_sg_packet
// Description  : Serialize a ScatterGather packet (create packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status serialize_sg_packet(SG_Node_ID loc, SG_Node_ID rem, SG_Block_ID blk,
                                     SG_System_OP op, SG_SeqNum sseq, SG_SeqNum rseq, char *data,
                                     char *packet, size_t *plen)
{

    int returnmsg = 0;
    init_message("./log_assign3.txt", "start serialize_sg_packet"); // initialize log

    // checking error
    if (loc == 0)
    {
        returnmsg = SG_PACKT_LOCID_BAD;
    }
    else if (rem == 0)
    {
        returnmsg = SG_PACKT_REMID_BAD;
    }
    else if (blk == 0)
    {
        returnmsg = SG_PACKT_BLKID_BAD;
    }
    else if (op < 0 || op >= SG_MAXVAL_OP)
    {
        returnmsg = SG_PACKT_OPERN_BAD;
    }
    else if (sseq == 0)
    {
        returnmsg = SG_PACKT_SNDSQ_BAD;
    }
    else if (rseq == 0)
    {
        returnmsg = SG_PACKT_RCVSQ_BAD;
    }
    write_message(returnmsg); //write error code in log
    if (returnmsg != 0)
    {
        return returnmsg; //return error code when it has error
    }
    //packet = (char*)malloc(sizeof(char) * SG_BASE_PACKET_SIZE); //packet was allocated!

    //copy from each component to packet
    int offset = 0;
    copy_32bit(packet + offset, SG_MAGIC_VALUE);
    offset += 4;
    copy_64bit(packet + offset, loc);
    offset += 8;
    copy_64bit(packet + offset, rem);
    offset += 8;
    copy_64bit(packet + offset, blk);
    offset += 8;
    copy_32bit(packet + offset, op);
    offset += 4;
    copy_16bit(packet + offset, sseq);
    offset += 2;
    copy_16bit(packet + offset, rseq);
    offset += 2;

    if (data != NULL)
    { // if there are data
        copy_8bit(packet + offset, 1);
        offset += 1;
        memcpy(packet + offset, data, SG_BLOCK_SIZE);
        offset += SG_BLOCK_SIZE;
        copy_32bit(packet, SG_MAGIC_VALUE);
        offset += 4;

        *plen = SG_DATA_PACKET_SIZE;
    }
    else
    { // if there's no data
        copy_8bit(packet + offset, 0);
        offset += 1;
        copy_32bit(packet, SG_MAGIC_VALUE);
        offset += 4;
        *plen = SG_BASE_PACKET_SIZE;
    }
    end_message("end serialize_sg_packet"); //ending log
    return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : deserialize_sg_packet
// Description  : De-serialize a ScatterGather packet (unpack packet)
//
// Inputs       : loc - the local node identifier
//                rem - the remote node identifier
//                blk - the block identifier
//                op - the operation performed/to be performed on block
//                sseq - the sender sequence number
//                rseq - the receiver sequence number
//                data - the data block (of size SG_BLOCK_SIZE) or NULL
//                packet - the buffer to place the data
//                plen - the packet length (int bytes)
// Outputs      : 0 if successfully created, -1 if failure

SG_Packet_Status deserialize_sg_packet(SG_Node_ID *loc, SG_Node_ID *rem, SG_Block_ID *blk,
                                       SG_System_OP *op, SG_SeqNum *sseq, SG_SeqNum *rseq, char *data,
                                       char *packet, size_t plen)
{

    init_message("./log_assign3_de.txt", "start deserialize_sg_packet"); // initalize log
    // copy from packet to each component   
    int offset = 0;
    uint32_t signature = get_32bit(packet + offset);
    offset += 4;
    *loc = get_64bit(packet + offset);
    offset += 8;
    *rem = get_64bit(packet + offset);
    offset += 8;
    *blk = get_64bit(packet + offset);
    offset += 8;
    *op = get_32bit(packet + offset);
    offset += 4;
    *sseq = get_16bit(packet + offset);
    offset += 2;
    *rseq = get_16bit(packet + offset);
    offset += 2;

    uint8_t dataBit = get_8bit(packet + offset);
    offset += 1;

    if (plen == SG_DATA_PACKET_SIZE)
    {
        memcpy(data, packet + offset, SG_BLOCK_SIZE);
    }

    write_message_packet(packet, plen); // log packet

    // check error
    int returnmsg = 0;
    if (*loc == 0)
    {
        returnmsg = SG_PACKT_LOCID_BAD;
    }
    else if (*rem == 0)
    {
        returnmsg = SG_PACKT_REMID_BAD;
    }
    else if (*blk == 0)
    {
        returnmsg = SG_PACKT_BLKID_BAD;
    }
    else if (*sseq == 0)
    {
        returnmsg = SG_PACKT_SNDSQ_BAD;
    }
    else if (*rseq == 0)
    {
        returnmsg = SG_PACKT_RCVSQ_BAD;
    }

    else if (*op < 0 || *op >= SG_MAXVAL_OP)
    {
        returnmsg = SG_PACKT_OPERN_BAD;
    }
    setRemoteNodeSeq(*rem, *rseq + 1);
    end_message("end deserialize_sg_packet"); // end log
    return returnmsg;
}

//
// Driver support functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : sgInitEndpoint
// Description  : Initialize the endpoint
//
// Inputs       : none
// Outputs      : 0 if successfull, -1 if failure

int sgInitEndpoint(void)
{

    // Local variables
    char initPacket[SG_BASE_PACKET_SIZE], recvPacket[SG_BASE_PACKET_SIZE];
    size_t pktlen, rpktlen;
    SG_Node_ID loc, rem;
    SG_Block_ID blkid;
    SG_SeqNum sloc, srem;
    SG_System_OP op;
    SG_Packet_Status ret;

    // Local and do some initial setup
    logMessage(LOG_INFO_LEVEL, "Initializing local endpoint ...");
    sgLocalSeqno = SG_INITIAL_SEQNO;

    // Setup the packet
    pktlen = SG_BASE_PACKET_SIZE;
    if ((ret = serialize_sg_packet(SG_NODE_UNKNOWN,  // Local ID
                                   SG_NODE_UNKNOWN,  // Remote ID
                                   SG_BLOCK_UNKNOWN, // Block ID
                                   SG_INIT_ENDPOINT, // Operation
                                   sgLocalSeqno++,   // Sender sequence number
                                   SG_SEQNO_UNKNOWN, // Receiver sequence number
                                   NULL, initPacket, &pktlen)) != SG_PACKT_OK)
    {
        logMessage(LOG_ERROR_LEVEL, "sgInitEndpoint: failed serialization of packet [%d].", ret);
        return (-1);
    }

    // Send the packet
    rpktlen = SG_BASE_PACKET_SIZE;
    if (sgServicePost(initPacket, &pktlen, recvPacket, &rpktlen))
    {
        logMessage(LOG_ERROR_LEVEL, "sgInitEndpoint: failed packet post");
        return (-1);
    }

    // Unpack the recieived data
    if ((ret = deserialize_sg_packet(&loc, &rem, &blkid, &op, &sloc,
                                     &srem, NULL, recvPacket, rpktlen)) != SG_PACKT_OK)
    {
        logMessage(LOG_ERROR_LEVEL, "sgInitEndpoint: failed deserialization of packet [%d]", ret);
        return (-1);
    }

    // Sanity check the return value
    if (loc == SG_NODE_UNKNOWN)
    {
        logMessage(LOG_ERROR_LEVEL, "sgInitEndpoint: bad local ID returned [%ul]", loc);
        return (-1);
    }

    // Set the local node ID, log and return successfully
    sgLocalNodeId = loc;
    logMessage(LOG_INFO_LEVEL, "Completed initialization of node (local node ID %lu", sgLocalNodeId);

    initSGCache(SG_MAX_CACHE_ELEMENTS);
    return (0);
}

