#include <pcap.h>
#include <stdio.h>
#include <string.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void TCP(const u_char* packet,uint8_t Len){
    u_char SRC[2],DST[2];
    for(int i=0;i<2;i++){
        SRC[i]=packet[Len+i];
        DST[i]=packet[Len+i+2];
    }
    uint16_t SRCP=SRC[0]*16*16+SRC[1];
    uint16_t DSTP=DST[0]*16*16+DST[1];
    printf("DST_PORT : %d\t",DSTP);
    printf("SRC_PORT : %d\n",SRCP);
    uint8_t LenT=((packet[Len+12]&0xf0)>>4)*4+Len-14;
    uint16_t Total=packet[16]*16*16+packet[17],Pay=LenT;
    if((Total-LenT)!=0){
        printf("TCP_PAYLOAD : ");
        for(int i=0;i<10;i++){
            printf("%02X ",packet[LenT+14+i]);
        }
        printf("\n-------------------------------------------------------------------------\n\n");
    }else
        printf("-------------------------------------------------------------------------\n\n");
}

void IP(const u_char* packet){
    u_char SRC[4],DST[4];
    uint8_t Proto=packet[23],Len=packet[14]-0x40;
    for(int i=0;i<4;i++){
        DST[i]=packet[i+26];
        SRC[i]=packet[i+30];
    }
    printf("DST_IP : %d.%d.%d.%d\t",DST[0],DST[1],DST[2],DST[3]);
    printf("SRC_IP : %d.%d.%d.%d\n",SRC[0],SRC[1],SRC[2],SRC[3]);
    if(Proto==06)
        TCP(packet,Len*4+14);
    else
        printf("-------------------------------------------------------------------------\n\n");
}

void Eth(const u_char* packet){
    u_char DST[6],SRC[6];
    uint8_t Type=packet[12]*16*16+packet[13];

    Type=packet[12]*16*16+packet[13];
    for(int i=0;i<6;i++){
        DST[i]=packet[i];
        SRC[i+6]=packet[i+6];
    }
    printf("DST_MAC : %02X:%02X:%02X:%02X:%02X:02X\t",DST[0],DST[1],DST[2],DST[3],DST[4],DST[5]);
    printf("SRC_MAC : %02X:%02X:%02X:%02X:%02X:02X\n",SRC[0],SRC[1],SRC[2],SRC[3],SRC[4],SRC[5]);
    if(Type==0x0800)
        IP(packet);
    else
        printf("-------------------------------------------------------------------------\n\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("-------------------------------------------------------------------------\n");
    Eth(packet);
  }

  pcap_close(handle);
  return 0;
}
