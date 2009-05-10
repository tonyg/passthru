/* Passthru.c -- passes through all communications on a given TCP/UDP port through
   to another host, logging all transmissions. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>

#include <event.h>

#include "buffer.h"
#include "dumpbytes.h"

typedef struct Configuration {
  int portnumber;
  int otherport;
  int pass_udp;
  int echo_udp;
  int pass_tcp;
  int have_otherhost;
  int hexmode;
  unsigned char otherhostaddr[4];
  char otherhostname[1024];
  struct timeval timeout;
} Configuration;

typedef struct Connection {
  BUFFER txfer_buf;
  int collecting_from;
  time_t last_read_time;

  /* index 0 is the incoming connection, index 1 the outgoing */
  char *name[2];
  int fd[2];
  struct event read_event[2];
} Connection;

typedef void (*event_handler_t)(int,short,void*);

static Configuration cfg;

static int tcpserv = -1;
static int udpserv = -1;
static struct event accept_event;
static struct event udp_event;

static void die(char const *format, ...) {
  va_list vl;
  va_start(vl, format);
  vfprintf(stderr, format, vl);
  va_end(vl);
  exit(1);
}

static void log_fmt(char *fmt, ...) {
  time_t t = time(NULL);
  char *timestr = ctime(&t);
  va_list vl;

  timestr[strlen(timestr) - 1] = '\0';
  printf("%s (%08lx): ", timestr, t);
  va_start(vl, fmt);
  vprintf(fmt, vl);
  va_end(vl);
  fflush(stdout);
}

static void log_time_fmt(time_t t, char *fmt, ...) {
  char *timestr = ctime(&t);
  va_list vl;

  timestr[strlen(timestr) - 1] = '\0';
  printf("%s (%08lx): ", timestr, t);
  va_start(vl, fmt);
  vprintf(fmt, vl);
  va_end(vl);
  fflush(stdout);
}

static void get_addr_name(char *namebuf, unsigned char *addr) {
  struct hostent *h = gethostbyaddr(addr, 4, AF_INET);

  if (h == NULL) {
    sprintf(namebuf, "%u.%u.%u.%u",
	    addr[0],
	    addr[1],
	    addr[2],
	    addr[3]
	    );
    return;
  }

  sprintf(namebuf, "%s", h->h_name);
}

static void dump_configuration_settings(void) {
  log_fmt("invoked as: passthru %s%s%s%s-p %d -o %d%s%s -f %g\n",
	  cfg.pass_udp ? "-u " : "",
	  cfg.echo_udp ? "-E " : "",
	  cfg.pass_tcp ? "-t " : "",
	  cfg.hexmode ? "-x " : "-b ",
	  cfg.portnumber,
	  cfg.otherport,
	  cfg.have_otherhost ? " -h " : "",
	  cfg.have_otherhost ? cfg.otherhostname : "",
	  (double) cfg.timeout.tv_sec + (double) cfg.timeout.tv_usec / 1000000.0);
  log_fmt("bound to port number %d\n",
	  cfg.portnumber);
  if (cfg.have_otherhost)
    log_fmt("will connect to port number %d on %s\n",
	    cfg.otherport, cfg.otherhostname);
}

static int parse_cmdline(int argc, char *argv[]) {
  int show_help = 0;
  int have_opt_o = 0;

  while (1) {
    switch (getopt(argc, argv, "uEtbxp:o:h:f:")) {
      case 'u':
	cfg.pass_udp = 1;
	continue;

      case 'E':
	cfg.echo_udp = 1;
	continue;

      case 't':
	cfg.pass_tcp = 1;
	continue;

      case 'b':
	cfg.hexmode = 0;
	continue;

      case 'x':
	cfg.hexmode = 1;
	continue;

      case 'p':
	cfg.portnumber = atoi(optarg);
	continue;

      case 'o':
	cfg.otherport = atoi(optarg);
	have_opt_o = 1;
	continue;

      case 'h': {
	struct hostent *h = gethostbyname(optarg);
	unsigned char addr[4];

	if (h == NULL) {
	  fprintf(stderr, "Host not found. Bailing out.\n");
	  break;
	}

	memcpy(addr, h->h_addr_list[0], sizeof(addr));
	get_addr_name(cfg.otherhostname, addr);
	memcpy(cfg.otherhostaddr, addr, sizeof(cfg.otherhostaddr));
	cfg.have_otherhost = 1;
	continue;
      }

      case 'f': {
	double seconds;
	seconds = strtod(optarg, NULL);
	cfg.timeout.tv_sec = (long) seconds;
	cfg.timeout.tv_usec = (long) ((seconds - cfg.timeout.tv_sec) * 1000000.0) % 1000000;
	continue;
      }

      case EOF:
	break;

      default:
	show_help = 1;
	break;
    }

    break;
  }

  if (!have_opt_o)
    cfg.otherport = cfg.portnumber;

  if (show_help || (!cfg.pass_udp && !cfg.pass_tcp)) {
    fprintf(stderr,
	    "Usage: passthru [-uEtbx] [-p portnumber] [-o destportnumber] [-h host_impersonated] [-f seconds]\n"
	    "\t-u\tPass UDP traffic through\n"
	    "\t-E\tEcho UDP traffic back to sender\n"
	    "\t-t\tPass TCP traffic through\n"
	    "\t-b\tDump results in binary format\n"
	    "\t-x\tDump results in hex format (default)\n"
	    "\t-p\tSpecify the port of TCP and/or UDP traffic to pass\n"
	    "\t-o\tSpecify the port to connect to at the destination\n"
	    "\t-h\tSpecify the host to pass through to\n"
	    "\t-f\tEnable and specify buffer flush interval in seconds\n"
	    "\tYou must select either -u or -t (or both).\n"
	    );
    return 0;
  }

  dump_configuration_settings();
  return 1;
}

/*
#define NONBLOCKIFY(fd)	fcntl((fd), F_SETFL, fcntl((fd), F_GETFL, 0) | O_NONBLOCK)
*/

static void dump_buffer(Connection *c) {
  if (c->collecting_from != -1) {
    log_time_fmt(c->last_read_time,
		 "TCP: fd %d (%c; %s) sent %d bytes:\n", 
		 c->fd[c->collecting_from],
		 c->collecting_from == 0 ? 'I' : 'O',
		 c->name[c->collecting_from],
		 c->txfer_buf->pos);
    dump_buffer_to_stdout(c->txfer_buf->buf, c->txfer_buf->pos, cfg.hexmode);
    fflush(stdout);
    c->txfer_buf->pos = 0;
    c->collecting_from = -1;
  }
}

static void setup_other_sockaddr(struct sockaddr_in *s) {
  s->sin_family = AF_INET;
  memcpy(&s->sin_addr.s_addr, cfg.otherhostaddr, sizeof(cfg.otherhostaddr));
  s->sin_port = htons(cfg.otherport);
}

static int open_otherhost(void) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in s;

  if (sock < 0) {
    die("Could not create outbound socket (errno %d: %s).\n",
	errno, strerror(errno));
  }

  setup_other_sockaddr(&s);

  if (connect(sock, (struct sockaddr *) &s, sizeof(s)) < 0) {
    die("Could not connect outbound socket (errno %d: %s).\n",
	errno, strerror(errno));
  }

  return sock;
}

static void close_conn(Connection *conn, int closing_fd) {
  if (conn->txfer_buf->pos != 0) {
    dump_buffer(conn);
  }
  event_del(&conn->read_event[0]);
  event_del(&conn->read_event[1]);
  close(conn->fd[0]);
  close(conn->fd[1]);
  log_fmt("connection to %s between I fd %d and O fd %d closed by fd %d\n",
	  conn->name[0], conn->fd[0], conn->fd[1], closing_fd);
  free(conn->name[0]);
  killbuf(conn->txfer_buf);
  free(conn);
}

static void handle_data(int fd, short what, Connection *conn, int side) {
  int from = conn->fd[side];
  int to = conn->fd[!side];
  char buf[4096];
  int nread;

  event_add(&conn->read_event[side], &cfg.timeout);

  if ((what & EV_TIMEOUT) != 0) {
    dump_buffer(conn);
    return;
  }

  if (conn->collecting_from != side) {
    dump_buffer(conn);
  }

  nread = read(from, buf, sizeof(buf));
  switch (nread) {
    case 0:
      close_conn(conn, from);
      break;

    case -1:
      if (errno != EAGAIN && errno != EINTR) {
	close_conn(conn, -1);
      }
      break;

    default:
      if (cfg.have_otherhost) {
	if (write(to, buf, nread) != nread) {
	  die("Write to fd %d failed: %d (%s)\n", errno, strerror(errno));
	}
      }
      buf_append_n(conn->txfer_buf, buf, nread);
      conn->last_read_time = time(NULL);
      conn->collecting_from = side;
      break;
  }
}

static void handle_data0(int fd, short what, Connection *conn) {
  handle_data(fd, what, conn, 0);
}

static void handle_data1(int fd, short what, Connection *conn) {
  handle_data(fd, what, conn, 1);
}

static void accept_connection(int fd, short what, void *arg) {
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int newfd = accept(fd, (struct sockaddr *) &addr, &addrlen);
  Connection *conn;

  if (newfd < 0)
    return;

  conn = calloc(sizeof(Connection), 1);

  conn->txfer_buf = newbuf(4096);
  conn->collecting_from = -1;
  conn->last_read_time = 0;

  conn->name[0] = malloc(1024);
  conn->fd[0] = newfd;
  get_addr_name(conn->name[0], (unsigned char *) &addr.sin_addr.s_addr);
  event_set(&conn->read_event[0], conn->fd[0], EV_READ | EV_PERSIST,
	    (event_handler_t) handle_data0, conn);

  conn->name[1] = cfg.otherhostname;
  conn->fd[1] = open_otherhost();
  event_set(&conn->read_event[1], conn->fd[1], EV_READ | EV_PERSIST,
	    (event_handler_t) handle_data1, conn);

  log_fmt("connection accepted on I fd %d from %s to O fd %d\n",
	  newfd, conn->name[0], conn->fd[1]);

  event_add(&conn->read_event[0], &cfg.timeout);
  event_add(&conn->read_event[1], &cfg.timeout);
}

#define DGRAM_MSGBUF_LEN 65536
static void handle_datagram(int fd, short what, void *arg) {
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  char msgbuf[DGRAM_MSGBUF_LEN];
  int msglen;
  char newname[1024];

  if ((msglen = recvfrom(fd, msgbuf, DGRAM_MSGBUF_LEN, 0,
			 (struct sockaddr *) &addr, &addrlen)) >= 0) {
    get_addr_name(newname, (unsigned char *) &addr.sin_addr.s_addr);

    log_fmt("UDP: %s sent %d bytes:\n", newname, msglen);
    dump_buffer_to_stdout(msgbuf, msglen, cfg.hexmode);
    fflush(stdout);

    if (cfg.echo_udp) {
      if (sendto(fd, msgbuf, msglen, 0, (struct sockaddr *) &addr, addrlen) == -1)
	log_fmt("UDP: echo failed, errno = %d\n", errno);
      else
	log_fmt("UDP: echo succeeded\n");
    }

    if (cfg.have_otherhost) {
      struct sockaddr_in oa;

      setup_other_sockaddr(&oa);

      if (sendto(fd, msgbuf, msglen, 0, (struct sockaddr *) &oa, sizeof(oa)) == -1)
	log_fmt("UDP: pass through failed, errno = %d\n", errno);
      else
	log_fmt("UDP: pass through succeeded\n");
    }
  }
}

static void flush_all_f_buffers(int signo) {
  log_fmt("interrupted with signal %d\n", signo);
  fflush(NULL);
  exit(0);
}

static int init_socket(int type, char *kind, int should_listen) {
  int serv = socket(AF_INET, type, 0);
  struct sockaddr_in s;

  if (serv < 0) {
    die("Could not open %s server socket.\n", kind);
  }

  s.sin_family = AF_INET;
  s.sin_addr.s_addr = htonl(INADDR_ANY);
  s.sin_port = htons(cfg.portnumber);

  {
    int i = 1; // 1 == turn on the option
    setsockopt(serv, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)); // don't care if this fails
  }

  if (bind(serv, (struct sockaddr *) &s, sizeof(s)) < 0) {
    die("Could not bind %s server socket.\n", kind);
  }

  if (should_listen) {
    if (listen(serv, 5) < 0) {
      int savedErrno = errno;
      die("Could not listen on %s server socket (errno %d: %s).\n",
	  kind, savedErrno, strerror(savedErrno));
    }
  }

  /*
  NONBLOCKIFY(serv);
  */

  return serv;
}

static void init_passthru(void) {
  if (cfg.pass_tcp) {
    tcpserv = init_socket(SOCK_STREAM, "TCP", 1);
    event_set(&accept_event, tcpserv, EV_READ | EV_PERSIST, accept_connection, NULL);
    event_add(&accept_event, NULL);
  }

  if (cfg.pass_udp) {
    udpserv = init_socket(SOCK_DGRAM, "UDP", 0);
    event_set(&udp_event, udpserv, EV_READ | EV_PERSIST, handle_datagram, NULL);
    event_add(&udp_event, NULL);
  }
}

int main(int argc, char *argv[]) {
  cfg.portnumber = cfg.otherport = 80;
  cfg.pass_udp = cfg.echo_udp = 0;
  cfg.pass_tcp = 0;
  cfg.have_otherhost = 0;
  cfg.hexmode = 1;
  cfg.timeout.tv_sec = 1; cfg.timeout.tv_usec = 0;
  memset(cfg.otherhostaddr, 0, sizeof(cfg.otherhostaddr));

  if (!parse_cmdline(argc, argv))
    return EXIT_FAILURE;

  event_init();
  init_passthru();
  fflush(NULL);
  signal(SIGINT, flush_all_f_buffers);
  event_dispatch();
  return EXIT_SUCCESS;
}
