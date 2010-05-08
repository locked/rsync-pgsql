#ifndef __LOG_PGSQL_P_H__
#define __LOG_PGSQL_P_H__ 1

#include <libpq-fe.h>

static char *server;
static char *port_s;
static int port = 5433;
static char *user;
static char *pw;
static char *db;

static char *crypto;
static char *sqlreq_getpw;
static char *sqlreq_getuid;
static char *sqlreq_getgid;
static char *sqlreq_getdir;
static char *sql_default_uid;
static char *sql_default_gid;
static signed char server_down;

static ConfigKeywords pgsql_config_keywords[] = {
    { "PGSQLServer", &server },
    { "PGSQLPort", &port_s },
    { "PGSQLUser", &user },
    { "PGSQLPassword", &pw },
    { "PGSQLDatabase", &db },    
    { "PGSQLCrypt", &crypto },
    { "PGSQLGetPW", &sqlreq_getpw },
    { "PGSQLGetUID", &sqlreq_getuid },
    { "PGSQLDefaultUID", &sql_default_uid },
    { "PGSQLGetGID", &sqlreq_getgid },
    { "PGSQLDefaultGID", &sql_default_gid },
    { "PGSQLGetDir", &sqlreq_getdir },
    { NULL, NULL }
};

#endif
