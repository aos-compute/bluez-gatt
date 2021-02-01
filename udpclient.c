
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

int send_udp_msg(const char* msg)
{
    int sockfd;
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        return -1;
    } 

    char buffer[MAXLINE]; 
    char *hello = "{ \
        \"linearAccelAxis\": { \
            \"value\": 0, \
            \"min\": 0, \
            \"max\": 5, \
            \"center\": 0, \
            \"deadband\": 0 \
        }, \
        \"angularAccelAxis\": { \ 
            \"value\": 0, \
            \"min\": 0, \
            \"max\": 3, \ 
            \"center\": 0, \
            \"deadband\": 0 \
        }, \
        \"deadManSwitch\": { \
            \"active\": true, \
            \"enabled\": false \
        }, \
        \"taskCompleteButton\": false, \
        \"incrementSubtaskButton\": false, \
        \"decrementSubTaskButton\": false, \
        \"requestNewTaskButton\": false, \
        \"axes\": [ \
            0, \
            0, \
            0, \
            0 \
        ], \
        \"buttons\": [ \
            { \
            \"pressed\": false, \
            \"touched\": false \
            }, \
            { \
            \"pressed\": false, \
            \"touched\": false \
            }, \
            { \
            \"pressed\": false, \
            \"touched\": false \
            }, \
            { \
            \"pressed\": false, \
            \"touched\": false \
            } \
        ] \
        }";
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

    close(sockfd);
  
    return 0; 
} 
