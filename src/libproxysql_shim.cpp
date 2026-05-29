#include "libproxysql.h"

static proxysql_virual_connection_list global_conn_list;
nolibc_lock glob_conn_mutex;

int setup_virual_connection(int sockfd, struct sockaddr *addr){
    glob_conn_mutex.lock();
    if(global_conn_list.head==NULL){
        proxysql_virual_connection* new_conn = new proxysql_virual_connection();
        new_conn->client_fd = sockfd;
        new_conn->server_fd = -1;
        new_conn->addr = *addr;
        new_conn->next = NULL;
        new_conn->client_to_server_buffer.buffer_head = new_conn->client_to_server_buffer.buffer;
        new_conn->client_to_server_buffer.buffer_tail = new_conn->client_to_server_buffer.buffer_head;
        memset(new_conn->client_to_server_buffer.buffer, 0, MAX_BUFFER_SIZE);
        new_conn->server_to_client_buffer.buffer_head = new_conn->server_to_client_buffer.buffer;
        new_conn->server_to_client_buffer.buffer_tail = new_conn->server_to_client_buffer.buffer_head;
        memset(new_conn->server_to_client_buffer.buffer, 0, MAX_BUFFER_SIZE);
        
        global_conn_list.head = new_conn;
        global_conn_list.tail = new_conn;
        glob_conn_mutex.unlock();
        return 0;
    }

    proxysql_virual_connection *conn = find_virtual_connection(addr);
    if(conn){
        glob_conn_mutex.unlock();
        return -1;
    }

    proxysql_virual_connection* new_conn = new proxysql_virual_connection();
    new_conn->client_fd = sockfd;
    new_conn->server_fd = -1;
    new_conn->addr = *addr;
    new_conn->next = NULL;
    global_conn_list.tail->next = new_conn;
    global_conn_list.tail = new_conn;
    glob_conn_mutex.unlock();
    return 0;
}

int accept_connection(int fd, struct sockaddr* addr){
    glob_conn_mutex.lock();
    proxysql_virual_connection* conn = find_virtual_connection(addr);
    if(conn){
        conn->server_fd = fd;
        glob_conn_mutex.unlock();
        return 0;
    }
    glob_conn_mutex.unlock();
    return -1;
}

void clear_virual_connection(int fd){
    glob_conn_mutex.lock();
    if (global_conn_list.head == NULL) {
        glob_conn_mutex.unlock();
        return;
    }
    if (global_conn_list.head->client_fd == fd) {
        proxysql_virual_connection* c = global_conn_list.head;
        c->server_to_client_buffer.mutex.lock();
        c->client_to_server_buffer.mutex.lock();
        global_conn_list.head = c->next;
        if (global_conn_list.tail == c){
            global_conn_list.tail = global_conn_list.head;
        }
        c->server_to_client_buffer.mutex.unlock();
        c->client_to_server_buffer.mutex.unlock();
        delete c;
        glob_conn_mutex.unlock();
        return;
    }

    for (proxysql_virual_connection* conn = global_conn_list.head; conn->next != NULL; conn = conn->next) {

        if (conn->next->client_fd == fd) {
            proxysql_virual_connection* c = conn->next;
            c->server_to_client_buffer.mutex.lock();
            c->client_to_server_buffer.mutex.lock();
            conn->next = c->next;
            if (global_conn_list.tail == c){
                global_conn_list.tail = conn;
            }
            c->server_to_client_buffer.mutex.unlock();
            c->client_to_server_buffer.mutex.unlock();
            delete c;
            glob_conn_mutex.unlock();
            return;
        }
    }
    glob_conn_mutex.unlock();
}


proxysql_virual_connection* find_virtual_connection(struct sockaddr *addr){
    if(global_conn_list.head == NULL){
        return NULL;
    }
    if (addr->sa_family != AF_INET){
        return NULL;
    }

    struct sockaddr_in *in = (struct sockaddr_in *)addr;
    
    for(proxysql_virual_connection* conn = global_conn_list.head;conn != NULL;conn = conn->next){
        if (conn->addr.sa_family != AF_INET) continue;
        return conn;
    }
    return NULL;
}

proxysql_virual_connection* find_virtual_connection_by_fd(int fd, bool is_client){
    if(global_conn_list.head == NULL){
        return NULL;
    } 
    for(proxysql_virual_connection* conn = global_conn_list.head;conn != NULL;conn = conn->next){
        if(is_client){
            if(conn->client_fd==fd){
                return conn;
            }
        }
        if(conn->server_fd==fd){
            return conn;
        }
    }
    return NULL;
}

int virtual_poll(int fd, bool is_client){
    glob_conn_mutex.lock();
    proxysql_virual_connection* conn = find_virtual_connection_by_fd(fd, is_client);
    glob_conn_mutex.unlock();
    while(conn->server_fd==-1);
    if(!conn){
        return -1;
    }

    if(is_client){
        //conn->server_to_client_buffer.mutex.lock();
        if(conn->server_to_client_buffer.buffer_tail!=conn->server_to_client_buffer.buffer_head){
            //conn->server_to_client_buffer.mutex.unlock();
            return 0;
        }
        //non_libc_print_size_t("server_to_client_buffer size", (conn->server_to_client_buffer.buffer_tail - conn->server_to_client_buffer.buffer_head));
        //conn->server_to_client_buffer.mutex.unlock();
    }else{
        //conn->client_to_server_buffer.mutex.lock();
        if(conn->client_to_server_buffer.buffer_tail!=conn->client_to_server_buffer.buffer_head){
            //conn->client_to_server_buffer.mutex.unlock();
            return 0;
        }
        //non_libc_print_size_t("client_to_server_buffer size", (conn->server_to_client_buffer.buffer_tail - conn->server_to_client_buffer.buffer_head));
        //conn->client_to_server_buffer.mutex.unlock();
    }
    return 1;
}

static int read_from_msg_buff(struct msg_buffer* msg_buff, void* buffer, int len){
    if(len > (msg_buff->buffer_tail - msg_buff->buffer_head)){
        len = msg_buff->buffer_tail - msg_buff->buffer_head;
    }

    memcpy(buffer, msg_buff->buffer_head, len);
    msg_buff->buffer_head += len;
    nolibc_assert(msg_buff->buffer_head <= msg_buff->buffer_tail);
    if(msg_buff->buffer_head == msg_buff->buffer_tail){
        msg_buff->buffer_head = msg_buff->buffer;
        msg_buff->buffer_tail = msg_buff->buffer;
    }
    return len;
}

int virtual_read(int fd, void* buffer, int len, bool is_client){
    glob_conn_mutex.lock();
    proxysql_virual_connection* conn = find_virtual_connection_by_fd(fd, is_client);
    glob_conn_mutex.unlock();
    while(conn->server_fd==-1);
    if(!conn){
        return -1;
    }

    int res = 1;
    while(res != 0){
        res = virtual_poll(fd, is_client);
        if(res == -1) return res;
    }


    if(is_client){
        conn->server_to_client_buffer.mutex.lock();
        res = read_from_msg_buff(&conn->server_to_client_buffer, buffer, len);
        conn->server_to_client_buffer.mutex.unlock();
    }else{
        conn->client_to_server_buffer.mutex.lock();
        res = read_from_msg_buff(&conn->client_to_server_buffer, buffer, len);
        conn->client_to_server_buffer.mutex.unlock();
    }
    return res;
}

static int write_to_msg_buff(struct msg_buffer* msg_buff, void* buffer, int len){
    if(&msg_buff->buffer[MAX_BUFFER_SIZE-1] - msg_buff->buffer_tail < len)return -1;
    memcpy(msg_buff->buffer_tail, buffer, len);
    msg_buff->buffer_tail += len;
    return len;
}

int virtual_write(int fd, void* msg, int len, bool is_client){
    glob_conn_mutex.lock();
    proxysql_virual_connection* conn = find_virtual_connection_by_fd(fd, is_client);
    glob_conn_mutex.unlock();
    while(conn->server_fd==-1);
    if(!conn){
        return -1;
    }
    int res;
    if(is_client){
        conn->client_to_server_buffer.mutex.lock();
        res = write_to_msg_buff(&conn->client_to_server_buffer, msg, len);
        conn->client_to_server_buffer.mutex.unlock();
    }else{
        conn->server_to_client_buffer.mutex.lock();
        res = write_to_msg_buff(&conn->server_to_client_buffer, msg, len);
        conn->server_to_client_buffer.mutex.unlock();
    }
    return res;
}