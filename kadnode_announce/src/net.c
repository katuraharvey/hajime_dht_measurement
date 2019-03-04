
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h> /* close */
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <limits.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"

#define RECV_BUF_SIZE 1048576

struct task_t {
	int fd;
	net_callback *callback;
};

struct task_t tasks[16];
int numtasks = 0;

void net_add_handler( int fd, net_callback *callback ) {

	if( numtasks >= 16 ) {
		log_err( "NET: Too many file descriptors registered." );
		return;
	}

	tasks[numtasks].fd = fd;
	tasks[numtasks].callback = callback;
	numtasks++;
}

/* Set a socket non-blocking */
int net_set_nonblocking( int sock ) {
	int rc;
	int nonblocking = 1;

	rc = fcntl( sock, F_GETFL, 0 );
	if( rc < 0 ) {
		return -1;
	}

	rc = fcntl( sock, F_SETFL, nonblocking ? (rc | O_NONBLOCK) : (rc & ~O_NONBLOCK) );
	if( rc < 0 ) {
		return -1;
	}

	return 0;
}

int net_socket( const char name[], const char ifname[], int protocol, int af ) {
	int sock;

	if( protocol == IPPROTO_TCP ) {
		sock = socket( af, SOCK_STREAM, IPPROTO_TCP );
	} else if( protocol == IPPROTO_UDP ) {
		sock = socket( af, SOCK_DGRAM, IPPROTO_UDP );
	} else {
		sock = -1;
	}

	if( sock < 0 ) {
		log_err( "%s: Failed to create socket: %s", name, strerror( errno ) );
		return -1;
	}

	if( net_set_nonblocking( sock ) < 0 ) {
		close( sock );
		log_err( "%s: Failed to make socket nonblocking: '%s'", name, strerror( errno ) );
		return -1;
	}

#if defined(__APPLE__) || defined(__CYGWIN__) || defined(__FreeBSD__)
	if( ifname ) {
		close( sock );
		log_err( "%s: Bind to device not supported on Windows and MacOSX.", name );
		return -1;
	}
#else
	if( ifname && setsockopt( sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen( ifname ) ) ) {
		close( sock );
		log_err( "%s: Unable to bind to device '%s': %s", name, ifname, strerror( errno ) );
		return -1;
	}
#endif

	const int optval = 1;
	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval) ) < 0 ) {
		close( sock );
		log_err( "%s: Unable to set SO_REUSEADDR for '%s': %s", name, strerror( errno ) );
		return -1;
	}

    // Set socket to use larger recv buffer
    int recv_buf_size = RECV_BUF_SIZE;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, (socklen_t)sizeof(int))) {
		log_err( "%s: Unable to set SO_RCVBUF for '%s': %s", name, strerror( errno ) );
		return -1;
	}

	return sock;
}

int net_bind(
	const char name[],
	const char addr[],
	const char port[],
	const char ifname[],
	int protocol, int af
) {
	char addrbuf[FULL_ADDSTRLEN+1];
	const int opt_on = 1;
	int sock;
	socklen_t addrlen;
	IP sockaddr;

	if( addr_parse( &sockaddr, addr, port, af ) != 0 ) {
		log_err( "%s: Failed to parse IP address '%s' and port '%s'.",
			name, addr, port
		);
		return -1;
	}

	if( (sock = net_socket( name, ifname, protocol, sockaddr.ss_family )) < 0 ) {
		return -1;
	}

	if( sockaddr.ss_family == AF_INET6 ) {
		if( setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt_on, sizeof(opt_on) ) < 0 ) {
			close( sock );
			log_err( "%s: Failed to set socket option IPV6_V6ONLY: '%s' (%s)",
				name, strerror( errno ), str_addr( &sockaddr, addrbuf ) );
			return -1;
		}
	}

	addrlen = addr_len( &sockaddr );
	if( bind( sock, (struct sockaddr*) &sockaddr, addrlen ) < 0 ) {
		close( sock );
		log_err( "%s: Failed to bind socket to address: '%s' (%s)",
			name, strerror( errno ), str_addr( &sockaddr, addrbuf )
		);
		return -1;
	}

	if( protocol == IPPROTO_TCP && listen( sock, 5 ) < 0 ) {
		close( sock );
		log_err( "%s: Failed to listen on socket: '%s' (%s)",
			name, strerror( errno ), str_addr( &sockaddr, addrbuf )
		);
		return -1;
	}

	log_info( ifname ? "%s: Bind to %s, interface %s" : "%s: Bind to %s",
		name, str_addr( &sockaddr, addrbuf ), ifname
	);

	return sock;
}

void net_loop( void ) {
	int i;
	int rc;
	fd_set fds_working;
	fd_set fds;
	int max_fd = -1;

	struct timeval tv;

	FD_ZERO( &fds );

	for( i = 0; i < numtasks; ++i ) {
		struct task_t *task = &tasks[i];
		if( task->fd >= 0 ) {
			if( task->fd > max_fd ) {
				max_fd = task->fd;
			}
			FD_SET( task->fd, &fds );
		}
	}

	while( gconf->is_running ) {

		/* Wait one second for inconing traffic */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* Update clock */
		gettimeofday( &gconf->time_now, NULL );

		/* Get a fresh copy */
		memcpy( &fds_working, &fds, sizeof(fd_set) );

		rc = select( max_fd + 1, &fds_working, NULL, NULL, &tv );

		if( rc < 0 ) {
			if( errno == EINTR ) {
				continue;
			} else {
				log_err( "NET: Error using select: %s", strerror( errno ) );
				return;
			}
		}

		for( i = 0; i < numtasks; ++i ) {
			struct task_t *task = &tasks[i];
			if( task->fd >= 0 && FD_ISSET( task->fd, &fds_working ) ) {
				task->callback( rc, task->fd );
			} else {
				task->callback( 0, task->fd );
			}
		}
	}

	/* Close sockets and FDs */
	for( i = 0; i < numtasks; ++i ) {
		close( tasks[i].fd );
	}
}
