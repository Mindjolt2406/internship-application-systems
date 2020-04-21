// Name: Rathin Bhargava
// Source: https://ide.geeksforgeeks.org/HAoytQZ12B
#include<bits/stdc++.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/ip.h> 
#include <arpa/inet.h> 
#include <netdb.h> 
#include <unistd.h> 
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 

using namespace std;

// ping packet size
#define PING_PKT_SIZE 64

// automatic port number
#define PORT_NO 0

// ping sleep rate
#define PING_SLEEP_RATE 1000000

// Timeout delay in recieving packets
#define RECV_TIMEOUT 1

int pingloop = 1;



// ping packet struct
typedef struct ping_pkt
{
  struct icmp hdr; 
  char msg[PING_PKT_SIZE - sizeof(struct icmp)];
} ping_pkt;

// Calculate the checksum
// Calculating the Check Sum 
unsigned short checksum(void *b, int len) 
{    
  unsigned short *buf = (unsigned short*)b; 
  unsigned int sum=0; 
  unsigned short result; 
  
  for ( sum = 0; len > 1; len -= 2 )  sum += *buf++; 
  if ( len == 1 ) sum += *(unsigned char*)buf; 
  sum = (sum >> 16) + (sum & 0xFFFF); 
  sum += (sum >> 16); 
  result = ~sum; 
  return result; 
} 

void intHandler(int dummy)
{
  pingloop = 0;
}

char* dns_lookup(char* addr_host, struct sockaddr_in *addr_con)
{
  printf("\nResolving host %s\n", addr_host);
  struct hostent* host_entity = gethostbyname(addr_host);
  char* ip = (char*)malloc(NI_MAXHOST*sizeof(char));
  int i;

  if(host_entity == NULL) return NULL;

  strcpy(ip,inet_ntoa(*(struct in_addr*)host_entity->h_addr));

  (*addr_con).sin_family = host_entity->h_addrtype;
  (*addr_con).sin_port = htons(PORT_NO);
  (*addr_con).sin_addr.s_addr = *(long*)host_entity->h_addr;

  return ip;
}

char* reverse_dns_lookup(char* ip_addr)
{
  struct sockaddr_in temp_addr;
  socklen_t len;
  char buf[NI_MAXHOST], *ret_buf;

  temp_addr.sin_family = PF_INET;
  temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
  len = sizeof(struct sockaddr_in);

  if(getnameinfo((struct sockaddr *) &temp_addr,len,buf,sizeof(buf),NULL,0,NI_NAMEREQD))
  {
    printf("\nCould not resolve reverse lookup of hostname\n");
    return NULL;
  }

  ret_buf = (char*)calloc(strlen(buf)+1,sizeof(char));
  strcpy(ret_buf,buf);
  return ret_buf;
}

void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char* rev_host, char* ping_ip, char* ping_dom,int ttl_val = 64)
{
  int msg_count = 0, i = 0, flag = 1, msg_received_count = 0;
  unsigned int addr_len = 0;

  struct ping_pkt pckt;
  struct sockaddr_in r_addr;
  struct timespec time_start, time_end, tfs, tfe;
  long double rtt_msec=0, total_msec = 0;
  struct timeval tv_out;
  tv_out.tv_sec = RECV_TIMEOUT;
  tv_out.tv_usec = 0;

  clock_gettime(CLOCK_MONOTONIC, &tfs);

  if(setsockopt(ping_sockfd, IPPROTO_IP, IP_TTL,&ttl_val,sizeof(ttl_val)) != 0)
  {
    printf("\nCouldn't set socket options to TTL\n");
    return;
  }
  else printf("\nSocket set to TTL...\n");

  setsockopt(ping_sockfd,SOL_SOCKET,SO_RCVTIMEO,(const char *)&tv_out, sizeof(tv_out));

  while(pingloop)
  {
    flag = 1;

    bzero(&pckt, sizeof(pckt));

    pckt.hdr.icmp_type = ICMP_ECHO;
    pckt.hdr.icmp_hun.ih_idseq.icd_id = getpid();
    for(i=0;i<sizeof(pckt.msg)-1;i++) pckt.msg[i] = i+'0';
    pckt.msg[i] = 0;
    pckt.hdr.icmp_hun.ih_idseq.icd_seq = msg_count++;
    pckt.hdr.icmp_cksum = checksum(&pckt,sizeof(pckt));

    usleep(PING_SLEEP_RATE); 

    clock_gettime(CLOCK_MONOTONIC,&time_start);
    if(sendto(ping_sockfd, &pckt, sizeof(pckt),0,(struct sockaddr *)ping_addr,sizeof(*ping_addr)) <= 0)
    {
      printf("\nPacket sending failed\n");
      flag = 0;
    }

    addr_len = sizeof(r_addr);

    if(recvfrom(ping_sockfd, &pckt, sizeof(pckt),0,(struct sockaddr *)&r_addr,&addr_len) <= 0 && msg_count > 1)
    {
      printf("\nPacket receive failed!\n");
    }
    else
    {
      clock_gettime(CLOCK_MONOTONIC,&time_end);
      double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
      rtt_msec = (time_end.tv_sec-time_start.tv_sec)*1000.0 + timeElapsed;

      if(flag)
      {
        if(!(pckt.hdr.icmp_type == 69 && pckt.hdr.icmp_code == 0))
        {
          printf("\nError... Packet received with ICMP type: %d and code: %d\n",pckt.hdr.icmp_type,pckt.hdr.icmp_code);
        }
        else
        {
          printf("%d bytes from %s (h: %s)(%s) msg_seq=%d ttl=%d rtt = %Lf ms.\n",PING_PKT_SIZE,ping_dom,rev_host,ping_ip,msg_count,ttl_val,rtt_msec);
          msg_received_count++;
        }
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &tfe);
  double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;
  total_msec = (tfe.tv_sec - tfs.tv_sec)*1000+timeElapsed;

  printf("\n==%s ping statistics===\n",ping_ip);
  printf("\n%d packets sent, %d packets received, %f percent packet loss.. Total time: %Lf ms. \n\n",msg_count,msg_received_count,((msg_count-msg_received_count)/msg_count)*100.0,total_msec);
}

int main(int argc, char *argv[])
{
  int sockfd;
  char *ip_addr, *reverse_hostname;
  struct sockaddr_in addr_con;
  int addrlen = sizeof(addr_con);
  int ttl = 64;

  if(argc != 2 && argc != 3)
  {
    printf("\nFormat %s <address>\nFormat %s <address>\n <timetolive>\n",argv[0],argv[0]);
    return 0;
  }

  if(argc == 3)
  {
    ttl = stoi(argv[2]);
  }

  ip_addr = dns_lookup(argv[1],&addr_con);
  if(ip_addr == NULL)
  {
    printf("\nCould not resolve host\n");
  }

  printf("\nThe IP address is %s\n", ip_addr);
  reverse_hostname = reverse_dns_lookup(ip_addr);
  if(!reverse_hostname)
  {
    return 0;
  }

  printf("\nTrying to connect to '%s' IP: %s\n",argv[1],ip_addr);
  printf("\nReverse Lookup domain: %s\n",reverse_hostname);

  sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
  cout << "socket: " << sockfd << endl;
  if(sockfd<0)
  {
    printf("\nSocket file descriptor has not been recieved\n");
    return 0;
  }
  else
  {
    printf("\nSocket file descriptor %d recieved\n",sockfd);
  }

  signal(SIGINT,intHandler);

  send_ping(sockfd,&addr_con,reverse_hostname,ip_addr,argv[1],ttl);
  return 0;
}

/*
nslookup -query=AAAA www.google.com
*/