#ifndef __UDP_CLIENT_H
#define __UDP_CLIENT_H

#define PORT     5555 
#define MAXLINE 2048 

int send_udp_msg(const char* linear, const char* angular, const char* taskCompleteButton);


#endif /* __UDP_CLIENT_H */