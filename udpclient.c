
// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include "udpclient.h"

int create_udp_socket()
{
    int sockfd;
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        return -1;
    } 
    return sockfd;
}

void destroy_udp_socket(int sockfd)
{
    close(sockfd);
}

int send_udp_msg(int sockfd, const char* msg)
{
    char buffer[MAXLINE]; 
    //char *hello = "Hello from client"; 
    struct sockaddr_in     servaddr; 
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
      
    int n, len; 

    printf("UDP msg is: %s", msg);
      
    sendto(sockfd, msg, strlen(msg), 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 
    printf("UDP message sent.\n"); 
          
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                MSG_WAITALL, (struct sockaddr *) &servaddr, 
                &len); 
    buffer[n] = '\0'; 
    printf("UDP Server : %s\n", buffer); 
  
    return 0; 
} 
