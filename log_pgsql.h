#ifndef __LOG_PGSQL_H__
#define __LOG_PGSQL_H__ 1

#define PASSWD_SQL_CRYPT "crypt"
#define PASSWD_SQL_CLEARTEXT "cleartext"
#define PASSWD_SQL_PGSQL "password"
#define PASSWD_SQL_MD5 "md5"
#define PASSWD_SQL_MD5SHA1 "md5sha1"
#define PASSWD_SQL_ANY "any"
#define PGSQL_DEFAULT_SERVER "localhost"
#define PGSQL_DEFAULT_PORT 5432
#define PGSQL_MAX_REQUEST_LENGTH ((size_t) 8192U)
#define PGSQL_TRANSACTION_START "BEGIN"
#define PGSQL_TRANSACTION_END "COMMIT"

//TRICK
#include "parser.h"
#include "crypto.h"

#include <stdio.h>

#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>

#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netdb.h>


#include "ipv4stack.h"

#include "log_pgsql_p.h"

int workaround_snprintf(char *str, size_t size, const char *format, ...);

//#define STORAGE_FAMILY(X) ((X).ss_family)
#define STORAGE_FAMILY(X) ((X).__ss_family)

#define STORAGE_SIN_ADDR(X) ((((struct sockaddr_in *) &(X))->sin_addr).s_addr)

#define SNCHECK(CALL, SIZE) (workaround_ ## CALL)
#define ISCTRLCODE(X) ((X) == 0x7f || ((unsigned char) (X)) < 32U)

#define sockaddr_storage sockaddr_in
#define NI_MAXHOST 1025
//#define NI_NUMERICHOST (1 << 0)A
#define NI_NUMERICSERV 2
#define NI_MAXSERV 32
//#define STORAGE_LEN(X) (STORAGE_FAMILY(X) == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#define STORAGE_LEN(X) sizeof(struct sockaddr_in)
//#define STORAGE_LEN(X) ((X).ss_len)

#define MSG_SQL_DOWN "sql down"
#define MSG_SQL_WRONG_PARMS "sql wrong params"


typedef struct AuthResult_ {
    int auth_ok;                       /* 0=no auth/login not found,1=ok,-1=auth failed */
    uid_t uid;
    gid_t gid;
    const char *dir;
    int slow_tilde_expansion;
} AuthResult;

char *pw_pgsql_escape_string(const char *from);

int pw_pgsql_connect(PGconn ** const id_sql_server);

int pw_pgsql_simplequery(PGconn * const id_sql_server, const char * const query);

char *pw_pgsql_getquery(PGconn * const id_sql_server,
                               const char * const orig_query,
                               const char * const account,
                               const char * const ip,
                               const char * const port,
                               const char * const peer_ip,
                               const char * const decimal_ip);

void pw_pgsql_parse(const char * const file);

void pw_pgsql_check(AuthResult * const result,
                    const char *account, const char *password,
                    const struct sockaddr_storage * const sa,
                    const struct sockaddr_storage * const peer);

void pw_pgsql_exit(void);

#endif
