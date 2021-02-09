
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

int send_udp_msg(const char* linear, const char* angular, const char* taskCompleteButton)
{
    int sockfd;
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        return -1;
    } 

    char buffer[MAXLINE]; 
    const char *json1 = "{ \
        \"type\": \"ISAAC.REQUEST\", \
        \"data\":{ \
        \"linearAccelAxis\": { \
            \"value\": ";

    const char* json2 = ", \
            \"min\": 0, \
            \"max\": 5, \
            \"center\": 0, \
            \"deadband\": 0 \
        }, \
        \"angularAccelAxis\": { \
            \"value\": ";

    const char* json3 = ", \
            \"min\": 0, \
            \"max\": 3, \
            \"center\": 0, \
            \"deadband\": 0 \
        }, \
        \"deadManSwitch\": { \
            \"active\": true, \
            \"enabled\": false \
        }, \
        \"taskCompleteButton\": ";

    const char* json4 = ", \
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
        } \
        }";
    struct sockaddr_in     servaddr; 
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
      
    int n, len; 

    char* msg = (char*) malloc(strlen(json1) + strlen(json2) + strlen(json3) + strlen(json4) +
     strlen(angular) + strlen(linear) + strlen(taskCompleteButton) + 1);

    strncat(msg, json1, strlen(json1) );
    strncat(msg, linear, strlen(linear) );
    strncat(msg, json2, strlen(json2) );
    strncat(msg, angular, strlen(angular) );
    strncat(msg, json3, strlen(json3) );
    strncat(msg, taskCompleteButton, strlen(taskCompleteButton) );
    strncat(msg, json4, strlen(json4) );
 
    // printf("UDP msg is: %s", msg);
      
    sendto(sockfd, msg, strlen(msg), 
        MSG_CONFIRM, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 
    printf("UDP message sent.\n"); 


    close(sockfd);
  
    return 0; 
} 
