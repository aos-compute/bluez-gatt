#ifndef __UDP_CLIENT_H
#define __UDP_CLIENT_H

#define PORT     5555 
#define MAXLINE 2048 

int create_udp_socket();

void destroy_udp_socket(int sockfd);

int send_udp_msg(int sockfd, const char* msg);


#endif /* __UDP_CLIENT_H */