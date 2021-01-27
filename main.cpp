// whatever - do with it what you want
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"

#include <ctype.h>
#include <getopt.h>
#include "signals.h"


#define NANO 1000000000L

// buf needs to store 30 characters
int timespec2str(char *buf, uint len, struct timespec *ts) {
    int ret;
    struct tm t;

    tzset();
    if (localtime_r(&(ts->tv_sec), &t) == NULL)
        return 1;

    ret = strftime(buf, len, "%F %T", &t);
    if (ret == 0)
        return 2;
    len -= ret - 1;

    ret = snprintf(&buf[strlen(buf)], len, ".%09ld", ts->tv_nsec);
    if (ret >= len)
        return 3;

    return 0;
}

#define WORD1_BYTEORDER_MASK   (0x81000081)
#define WORD1_SIGNALID_MASK    (0x00000004)
#define WORD1_COMPRESSED_MASK  (0x00000008)
#define WORD1_CHECKSUM_MASK    (0x00000010)
#define WORD1_PRIO_MASK        (0x00000060)
#define WORD1_MESSAGELEN_MASK  (0x00FFFF00)
#define WORD1_SIGNAL_LEN_MASK  (0x7C000000)
#define WORD1_FRAG_INF_MASK    (0x00000002)
#define WORD1_FRAG_INF2_MASK   (0x02000000)

#define WORD1_FRAG_INF_SHIFT   (1)
#define WORD1_SIGNALID_SHIFT   (2)
#define WORD1_COMPRESSED_SHIFT (3)
#define WORD1_CHECKSUM_SHIFT   (4)
#define WORD1_PRIO_SHIFT       (5)
#define WORD1_MESSAGELEN_SHIFT (8)
#define WORD1_FRAG_INF2_SHIFT  (25)
#define WORD1_SIGNAL_LEN_SHIFT (26)

#define WORD2_VERID_GSN_MASK   (0x000FFFFF)
#define WORD2_TRACE_MASK       (0x03f00000)
#define WORD2_SEC_COUNT_MASK   (0x0c000000)

#define WORD2_TRACE_SHIFT      (20)
#define WORD2_SEC_COUNT_SHIFT  (26)

#define WORD3_SENDER_MASK      (0x0000FFFF)
#define WORD3_RECEIVER_MASK    (0xFFFF0000)

#define WORD3_RECEIVER_SHIFT   (16)


uint32_t
getMessageLength(const uint32_t & word1){
  return (word1 & WORD1_MESSAGELEN_MASK) >> WORD1_MESSAGELEN_SHIFT;
}

uint32_t
getSignalIdIncluded(const uint32_t & word1){
  return (word1 & WORD1_SIGNALID_MASK) >> WORD1_SIGNALID_SHIFT;
}

struct SignalHeader {	
  uint32_t theVerId_signalNumber;    // 4 bit ver id - 16 bit gsn
  uint32_t theReceiversBlockNumber;  // Only 16 bit blocknum  
  uint32_t theSendersBlockRef;
  uint32_t theLength;
  uint32_t theSendersSignalId;
  uint32_t theSignalId;
  uint16_t theTrace;
  uint8_t  m_noOfSections;
  uint8_t  m_fragmentInfo;
}; /** 7x4 = 28 Bytes */

void
createSignalHeader(SignalHeader * const dst,
			      const uint32_t & word1, 
			      const uint32_t & word2, 
			      const uint32_t & word3){
  
  uint32_t signal_len = (word1 & WORD1_SIGNAL_LEN_MASK)>> WORD1_SIGNAL_LEN_SHIFT;
  uint32_t fragInfo1  = (word1 & WORD1_FRAG_INF_MASK) >> (WORD1_FRAG_INF_SHIFT-1);
  uint32_t fragInfo2  = (word1 & WORD1_FRAG_INF2_MASK) >> (WORD1_FRAG_INF2_SHIFT);
  uint32_t trace      = (word2 & WORD2_TRACE_MASK) >> WORD2_TRACE_SHIFT;
  uint32_t verid_gsn  = (word2 & WORD2_VERID_GSN_MASK);
  uint32_t secCount   = (word2 & WORD2_SEC_COUNT_MASK) >> WORD2_SEC_COUNT_SHIFT;
  
  dst->theTrace              = trace;
  dst->m_noOfSections        = secCount;
  dst->m_fragmentInfo        = fragInfo1 | fragInfo2;
  
  dst->theLength             = signal_len;
  dst->theVerId_signalNumber = verid_gsn;
  
  uint32_t sBlockNum  = (word3 & WORD3_SENDER_MASK);
  uint32_t rBlockNum  = (word3 & WORD3_RECEIVER_MASK) >> WORD3_RECEIVER_SHIFT;
  
  dst->theSendersBlockRef      = sBlockNum;
  dst->theReceiversBlockNumber = rBlockNum;
}

void usage(char * prg) {
  printf("Usage: %s -f <pcapfile>\n", prg);
}

int main(int argc, char* argv[])
{
  char filename[1024];

  for(;;)
  {
    switch(getopt(argc, argv, "h:f:"))
    {
      case 'f':
        strcpy(filename, optarg);
        continue;

      case -1:
        break;

      case '?':
      case 'h':
      default :
        usage(argv[0]);
        return 1;
    }
    break;
  }

  if (optind != argc)
  {
    printf("Something is wrong with your options\n");
    usage(argv[0]);
    return 1;
  }


  // open a pcap file for reading
  pcpp::PcapFileReaderDevice reader(filename);
  if (!reader.open())
  {
      printf("Error opening the pcap file\n");
      return 1;
  }

  int countdown = 3;

  pcpp::RawPacket rawPacket;
  while(reader.getNextPacket(rawPacket))
  {
    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    timespec tt = rawPacket.getPacketTimeStamp();

    char tbuf[256];
    timespec2str(tbuf, 256, &tt);

    // verify the packet is IPv4
    if (parsedPacket.isPacketOfType(pcpp::IPv4))
    {
        // extract source and dest IPs
        pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
        pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();

        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL)
        {
          //printf("Something went wrong, couldn't find TCP layer\n");
          continue;
        }

        int portDst = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
        if(portDst != 1186) {
          //continue;
        }

        pcpp::PayloadLayer* pPayload = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
        if (pPayload == NULL) {
          continue;
        }
        //printf("%s\n", pPayload->toString().c_str());
        uint8_t* p = pPayload->getPayload();
        size_t plen = pPayload->getPayloadLen();

        uint32_t sizeOfData = plen/4;
        uint32_t recvData[8048];

        int dstPort = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
        int srcPort = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);

        if (tcpLayer->getTcpHeader()->rstFlag == 1) {
          printf("%s '%s:%d' -> '%s:%d' [RST]\n\n", tbuf,
            srcIP.toString().c_str(), srcPort, 
            destIP.toString().c_str(), dstPort);
          continue;
        }
        if (tcpLayer->getTcpHeader()->finFlag == 1) {
          printf("%s '%s:%d' -> '%s:%d' [FIN]\n\n", tbuf,
            srcIP.toString().c_str(), srcPort, 
            destIP.toString().c_str(), dstPort);
          continue;
        }
        if (tcpLayer->getTcpHeader()->synFlag == 1) {
          printf("%s '%s:%d' -> '%s:%d' [SYN]\n\n", tbuf,
            srcIP.toString().c_str(), srcPort, 
            destIP.toString().c_str(), dstPort);
          continue;
        }

        if(srcPort == 3306 || dstPort == 3306) {
          printf("%s '%s:%d' -> '%s:%d' [%lu]", tbuf,
            srcIP.toString().c_str(), srcPort, 
            destIP.toString().c_str(), dstPort, plen);
          for(int i = 0; i < plen; i++) {
            if (isprint(p[i]))  printf("%c", p[i]); else printf(".");
          }
          printf("\n");
          continue;
        }
        if(plen % 4 != 0) {
          printf("%s '%s:%d' -> '%s:%d' [%lu]", tbuf,
            srcIP.toString().c_str(), srcPort, 
            destIP.toString().c_str(), dstPort, plen);
          for(int i = 0; i < plen; i++) {
            if (isprint(p[i]))  printf("%c", p[i]); else printf(".");
          }
          printf("\n");
          printf("Wrong payload len\n");
          continue;
        }

        if(strncmp((const char *)p, "ndbd", 4) == 0) {
          continue;
        }

        int l = 0;
        int total = 0;
        int msgId = 0;
        bool stop = false;

        while((l < sizeOfData) && (!stop)) {
          uint8_t * p4 = &p[l*4];
          recvData[0] = p4[0] | (p4[1] << 8) | (p4[2] << 16) | (p4[3] << 24);

          const uint16_t messageLen32    = getMessageLength(recvData[0]);

          // 26 is a random number choosen, no rational
          // but some messages are no signals and this filters them
          if(messageLen32 > 26) {
            stop = true;
            continue;
          }

          for(int i = 0; i < messageLen32; i++) {
            uint8_t * p4 = &p[l*4 + i*4];
            recvData[i] = p4[0] | (p4[1] << 8) | (p4[2] << 16) | (p4[3] << 24);
          }

          l += messageLen32;
          total += messageLen32;

          uint32_t * signalData = &recvData[3];

          SignalHeader sh;
          createSignalHeader(&sh, recvData[0], recvData[1], recvData[2]);

          if(getSignalIdIncluded(recvData[0]) == 0){
            sh.theSendersSignalId = ~0;
          } else {
            sh.theSendersSignalId = * signalData;
            signalData ++;
          }//if
          sh.theSignalId= ~0;

          //if (sh.theVerId_signalNumber == 247) {
          const char * sname = getSignalName(sh.theVerId_signalNumber, "NOT FOUND");

          printf("%s '%s:%d' -> '%s:%d' [%d, %04d] %s ", tbuf,
            srcIP.toString().c_str(), (int)ntohs(tcpLayer->getTcpHeader()->portSrc), 
            destIP.toString().c_str(), (int)ntohs(tcpLayer->getTcpHeader()->portDst), msgId, messageLen32, sname);
          for(int i = l; i < l + messageLen32; i++) {
            if (isprint(p[i]))  printf("%c", p[i]); else printf(".");
          }
          printf("\n");

          printf("Message length: %d signal number: %d, send signal id: %d, len: %d\n", messageLen32, 
            sh.theVerId_signalNumber,
            sh.theSendersSignalId, 
            sh.theLength);
          switch(sh.theVerId_signalNumber) {
            case GSN_EVENT_REP: {
              unsigned int et = signalData[0];
              printf("type: %d, node id: %d ", et & 0xFFFF, et >> 16);
              }
            default:
              for (int i = 0; i < sh.theLength; i++) {
                printf("%d ", signalData[i]);
              }
          }
          printf("\n\n");
            
          //}

          msgId++;

        }

//            printf("signal Data: %d\n", recvData[3]);
        //}
    }
  }

  // close the file
  reader.close();

  return 0;
}