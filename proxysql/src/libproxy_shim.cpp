#include <iostream>
#include <thread>
#include "btree_map.h"
#include "proxysql.h"

#include <random>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//#define PROXYSQL_EXTERN
#include "cpp.h"

#include "mysqld_error.h"

#include "ProxySQL_Statistics.hpp"
#include "MySQL_PreparedStatement.h"
#include "PgSQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
#include "SQLite3_Server.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Query_Cache.h"
#include "PgSQL_Query_Cache.h"
#include "proxysql_restapi.h"
#include "Web_Interface.hpp"
#include "proxysql_utils.h"
#include "PgSQL_Monitor.hpp"

#include "libdaemon/dfork.h"
#include "libdaemon/dsignal.h"
#include "libdaemon/dlog.h"
#include "libdaemon/dpid.h"
#include "libdaemon/dexec.h"
#include "ev.h"
#include "MySQL_Data_Stream.h"


#include "curl/curl.h"

#include "openssl/x509v3.h"

#include <sys/mman.h>

#include <uuid/uuid.h>
#include <atomic>
#include <cstring>

struct active_connection{
    int fd;
	int port;
	char ip[INET_ADDRSTRLEN];
	MySQL_Session sess;
    MySQL_Data_Stream ds;
};

std::vector<active_connection*> active_connections;

//return 1 if new connection is formed
int form_new_connection(char ip[], int port, int fd, active_connection** connection){
    for(int i = 0;i<active_connections.size();i++){
        active_connection* conn = active_connections[i];
        if(conn->port == port && std::strcmp(conn->ip, ip) == 0){
            *connection = conn;
            return 0;
        }
    }

    //make a new connection
    active_connection* conn = new active_connection{};
    conn->fd = fd;
    conn->port = port;
    std::strncpy(conn->ip, ip, INET_ADDRSTRLEN);
    conn->ip[INET_ADDRSTRLEN - 1] = '\0';
    conn->sess.client_myds = new MySQL_Data_Stream();
    conn->sess.client_myds->fd = fd;
	conn->sess.client_myds->init(MYDS_FRONTEND, &conn->sess, conn->sess.client_myds->fd);
    MySQL_Connection* myconn = new MySQL_Connection();
    conn->sess.client_myds->attach_connection(myconn);
    conn->sess.client_myds->myconn->set_is_client(); // this is used for prepared statements
    conn->sess.client_myds->myconn->myds = conn->sess.client_myds; // 20141011
	conn->sess.client_myds->myconn->fd = conn->sess.client_myds->fd; // 20141011
    conn->sess.client_myds->myprot.init(&conn->sess.client_myds, conn->sess.client_myds->myconn->userinfo, &conn->sess);
    uint32_t session_track_gtids_int = SpookyHash::Hash32(mysql_thread___default_session_track_gtids, strlen(mysql_thread___default_session_track_gtids), 10);
    conn->sess.client_myds->myconn->options.session_track_gtids_int = session_track_gtids_int;
    if (conn->sess.client_myds->myconn->options.session_track_gtids) {
        free(conn->sess.client_myds->myconn->options.session_track_gtids);
    }
    conn->sess.client_myds->myconn->options.session_track_gtids = strdup(mysql_thread___default_session_track_gtids);
    conn->sess.client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &conn->sess.thread_session_id, true);
    ioctl_FIONBIO(conn->sess.client_myds->fd, 1);
    conn->sess.writeout();

    active_connections.push_back(conn);
    return 1;
} 

void connect_handler(size_t arg1, size_t arg2, size_t arg3){
	struct sockaddr_in* addr = (struct sockaddr_in*)arg2;
	if(addr->sin_family != AF_INET)return;

	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
	int port = ntohs(addr->sin_port);

    active_connection* conn;
    if(form_new_connection(ip, port, arg1, &conn)==1){
        //new connection formed
        fprintf(stderr, "new conncetion formed\n");
        return;
    }

	return;
}