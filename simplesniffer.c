/* Simple Raw Sniffer                                                    */ 
/* Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  */
/* To compile: gcc simplesniffer.c -o simplesniffer -lpcap               */ 
/* Run as root!                                                          */ 
/*                                                                       */
/* This code is distributed under the GPL License. For more info check:  */
/* http://www.gnu.org/copyleft/gpl.html                                  */

#include <pcap.h> 
#include <stdlib.h> 
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <monetary.h>
#include <locale.h>


#define MAXBYTES2CAPTURE 2048 

int hash[800];
unsigned int globaldst[800];
long int sec[800];
long int msec[800];
int c;
void dump_stats();
/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 
 /*
 int i=0, *counter = (int *)arg; 

 printf("Packet Count: %d\n", ++(*counter)); 
 printf("Received Packet Size: %d\n", pkthdr->len); 
 printf("Payload:\n"); 
 for (i=0; i<pkthdr->len; i++){ 

    if ( isprint(packet[i]) ) //If it is a printable character, print it
        printf("%c ", packet[i]); 
    else 
        printf(". "); 
    
     if( (i%16 == 0 && i!=0) || i==pkthdr->len-1 ) 
        printf("\n"); 
  } 
 */
   unsigned int sip,dip;
   struct in_addr srcip,dstip;

   memcpy((unsigned char*)&dip,packet+30,4);
   //memcpy((unsigned char*)&sip,p+26,4);
   //srcip.s_addr = sip;
   dstip.s_addr = dip;
   if (hash[ntohl(dip)%800])
   {
//      printf("Already recorded DIP \n");
        return;
   }
   //gettimeofday(&cur_time, NULL);
   hash[ntohl(dip)%800] = 1;
   //printf(": [%s -> %s] \n", inet_ntoa(srcip),inet_ntoa(dstip));
   globaldst[ntohl(dip)%800] = dip;
   sec[ntohl(dip)%800] = pkthdr->ts.tv_sec; //cur_time.tv_sec;//s;
   msec[ntohl(dip)%800] = pkthdr->ts.tv_usec;//cur_time.tv_usec; //usec;
   c++;
   //if (c % 50 == 0) {
   //   printf("pfcount, DEBUG: %d\n", c);
   //}
   if (c >=767)
   {
        printf("pfcount, DEBUG: %d\n", c);
        dump_stats();
   }

 return; 
} 

/* ******************************** */

void dump_stats()
{
  FILE *f = fopen("packet_timestamp.txt","w");
  int i = 0;
  printf("Start Print \n");
  while (i++ < 800)
  {
        //printf("printing \n");
        struct in_addr dst = {0};
        dst.s_addr = globaldst[i];
        fprintf(f, "dst: %s sec %ld usec %ld\n", inet_ntoa(dst), sec[i], msec[i]);
  }
  printf("Stop Print \n");
  fclose(f);
}


/* main(): Main function. Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] ){ 
    
 int i=0, count=0; 
 pcap_t *descr = NULL; 
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
 memset(errbuf,0,PCAP_ERRBUF_SIZE); 

 struct bpf_program fp; //the complied filter
 char filter_exp[] = "ip or arp or icmp";//filter expression
 bpf_u_int32 mask; //Our net mask
 bpf_u_int32 net; //our IP

 if( argc > 1){  /* If user supplied interface name, use it. */
    device = argv[1];
 }
 else{  /* Get the name of the first device suitable for capture */ 
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
                 fprintf(stderr, "Can't get netmask for device %s\n", device);
                 net = 0;
                 mask = 0;
        }

    if ( (device = pcap_lookupdev(errbuf)) == NULL){
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
 }

 printf("Opening device %s\n", device); 
 
 /* Open device in promiscuous mode */ 
 if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
 }
 
 /* Compile and apply the filter */
        if (pcap_compile(descr, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));
                return(1);
        }
        if (pcap_setfilter(descr, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));
                return(1);
        }
 
 /* Loop forever & call processPacket() for every received packet*/ 
 if ( pcap_loop(descr, -1, processPacket, (u_char *)&count) == -1){
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
    exit(1);
 }

return 0; 

} 

/* EOF*/
