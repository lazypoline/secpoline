#include <sys/socket.h>
#include <cstring>
#include <random>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h> 
#include "segfault_handler.h"

#define MAX_BUFFER_SIZE 64*1024

struct msg_buffer{
    char buffer[MAX_BUFFER_SIZE]; //64kb
    char* buffer_head;
    char* buffer_tail;
    nolibc_lock mutex;
};

struct proxysql_virual_connection{
    int client_fd; //used by the application
    int server_fd; //used by the monitor
    struct msg_buffer client_to_server_buffer;
    struct msg_buffer server_to_client_buffer;
    struct sockaddr addr;
    proxysql_virual_connection* next;
};

struct proxysql_virual_connection_list{
    proxysql_virual_connection* head = NULL;
    proxysql_virual_connection* tail = NULL;
};


int main_constructor(void);
int main_destructor(void);
void connect_handler(size_t arg1, size_t arg2, size_t arg3);
void libproxysql_syscall_handler(size_t syscall_no, size_t arg1, size_t arg2, size_t arg3, size_t arg4, size_t arg5, size_t arg6);

int setup_virual_connection(int sockfd, struct sockaddr *addr);
proxysql_virual_connection* find_virtual_connection(struct sockaddr *addr);
void clear_virual_connection(int fd);
int accept_connection(int fd, struct sockaddr *addr);
proxysql_virual_connection* find_virtual_connection_by_fd(int fd, bool is_client);
int virtual_poll(int fd, bool is_client);
int virtual_read(int fd, void* buffer, int len, bool is_client);
int virtual_write(int fd, void* msg, int len, bool is_client);



