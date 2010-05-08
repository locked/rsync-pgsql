#include <config.h>

/* PostgreSQL backend, by Cindy Marasco <cindy@getaclue.org> */

//#ifdef WITH_PGSQL

#include "rsync.h"


#include "ipv4stack.h"
#include "parser.h"
#include "log_pgsql_p.h"
#include "log_pgsql.h"
//#include "messages.h"
#include "crypto.h"


#ifdef WITH_DMALLOC
# include <dmalloc.h>
#endif

static size_t prv_PQescapeString(char * const to, const char * const from,
                                 const size_t length)
{
    register const char *source = from;
    register char *target = to;
    size_t remaining = length;
    
    while (remaining > (size_t) 0U) {
        switch (*source) {
        case 0:
            remaining = (size_t) 1U;
            break;
        case '\r':
            *target++ = '\\';
            *target++ = 'r';            
            break;
        case '\n':
            *target++ = '\\';
            *target++ = 'n';
            break;
        case '\b':
            *target++ = '\\';
            *target++ = 'b';
            break;            
        case '\\':
        case '\'':
        case '"':
            *target++ = '\\';
        default:
            *target++ = *source;
        }
        source++;
        remaining--;        
    }    
    *target = 0;
    
    return (size_t) (target - to);
}

static int pw_pgsql_validate_name(const char *name)
{
    if (name == NULL || *name == 0) {
        return -1;
    }
    do {
        if ((*name >= 'a' && *name <= 'z') ||
            (*name >= 'A' && *name <= 'Z') ||
            (*name >= '0' && *name <= '9') ||
            *name == ' ' || *name == '-' ||
            *name == '_' || *name == '\'' || *name == '.' ||
            *name == ':' || *name == '@') {
            /* God bless the Perl 'unless' keyword */
        } else {
            return -1;
        }            
        name++;
    } while (*name != 0);
    
    return 0;
}

char *pw_pgsql_escape_string(const char *from)
{
    size_t from_len;
    size_t to_len;
    char *to;
    size_t tolen;    
            
    if (from == NULL) {
        return NULL;
    }
    from_len = strlen(from);
    to_len = from_len * 2U + (size_t) 1U;
    if ((to = malloc(to_len)) == NULL) {
        return NULL;
    }
    tolen = prv_PQescapeString(to, from, from_len);
    if (tolen >= to_len) {
        for (;;) {
            *to++ = 0;
        }
    }
    to[tolen] = 0;
                
    return to;
}

/*
 * Substitute digraphs for SQL requests.
 * orig_str is the original string, from the configuration file
 * full of \L, \I, \P, \R and \D.
 * query is a buffer to handle the result.
 * query_len is the size of the buffer.
 * returns the buffer @ if successful, NULL otherwise.   -frank.
 */

static char *sqlsubst(const char *orig_str, char * const query,
                      size_t query_len, const char * const user,
                      const char * const ip, const char * const port,
                      const char * const peer_ip,
                      const char * const decimal_ip)
{
    char *query_pnt = query;
    const char *orig_str_scan = orig_str;
    const size_t user_len = (user == NULL ? (size_t) 0U : strlen(user));
    const size_t ip_len = (ip == NULL ? (size_t) 0U : strlen(ip));
    const size_t port_len = (port == NULL ? (size_t) 0U : strlen(port));
    const size_t peer_ip_len = (peer_ip == NULL ? (size_t) 0U : strlen(peer_ip));
    const size_t decimal_ip_len = (decimal_ip == NULL ? (size_t) 0U : strlen(decimal_ip));

    while (*orig_str_scan != 0) {
        if (*orig_str_scan == '\\' && orig_str_scan[1] != 0) {
            orig_str_scan++;
            switch(tolower((unsigned char) *orig_str_scan)) {
            case 'l' :
                if (user_len >= query_len) {
                    return NULL;
                }
                if (user_len <= (size_t) 0U) {
                    goto nextone;
                }
                memcpy(query_pnt, user, user_len);
                query_pnt += user_len;
                query_len -= user_len;
                goto nextone;
            case 'i' :
                if (ip_len >= query_len) {
                    return NULL;
                }
                if (ip_len <= (size_t) 0U) {
                    goto nextone;
                }                
                memcpy(query_pnt, ip, ip_len);
                query_pnt += ip_len;
                query_len -= ip_len;
                goto nextone;
            case 'p' :             
                if (port_len >= query_len) {
                    return NULL;
                } 
                if (port_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, port, port_len);
                query_pnt += port_len;
                query_len -= port_len;
                goto nextone;
            case 'r' :             
                if (peer_ip_len >= query_len) {
                    return NULL;
                } 
                if (peer_ip_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, peer_ip, peer_ip_len);
                query_pnt += peer_ip_len;
                query_len -= peer_ip_len;
                goto nextone;
            case 'd' :             
                if (decimal_ip_len >= query_len) {
                    return NULL;
                } 
                if (decimal_ip_len <= (size_t) 0U) {
                    goto nextone;
                }               
                memcpy(query_pnt, decimal_ip, decimal_ip_len);
                query_pnt += decimal_ip_len;
                query_len -= decimal_ip_len;
                goto nextone;
            default :
                if (--query_len <= (size_t) 0U) {
                    return NULL;
                }
                *query_pnt++ = '\\';
            }
        }
        if (ISCTRLCODE(*orig_str_scan)) {
            goto nextone;
        }
        if (--query_len <= (size_t) 0U) {
            return NULL;
        }
        *query_pnt++ = *orig_str_scan;
        nextone:
        orig_str_scan++;
    }
    *query_pnt = 0;

    return query;
}

int pw_pgsql_connect(PGconn ** const id_sql_server)
{
    char *conninfo = NULL;
    size_t sizeof_conninfo;
    char *escaped_server = NULL;
    char *escaped_db = NULL;
    char *escaped_user = NULL;
    char *escaped_pw = NULL;
    int ret = -1;

    *id_sql_server = NULL;
    
	server = malloc(16);
	db = malloc(16);
	user = malloc(16);
	pw = malloc(16);
	snprintf( server, 10,"localhost");
	snprintf( db, 9,"fastprod");
	snprintf( user, 9,"fastprod");
	snprintf( pw, 9,"fastprod");
	
    if ((escaped_server = pw_pgsql_escape_string(server)) == NULL ||
        (escaped_db = pw_pgsql_escape_string(db)) == NULL ||        
        (escaped_user = pw_pgsql_escape_string(user)) == NULL ||
        (escaped_pw = pw_pgsql_escape_string(pw)) == NULL) {
			rprintf(FLOG,"ERR escaping\n");
        goto bye;
    }
	//rprintf(FLOG,"ERR conninfo:%s-%s\n",escaped_server,server);
    
#define PGSQL_CONNECT_FMTSTRING \
"host='%s' port='%d' dbname='%s' user='%s' password='%s'"
        
    sizeof_conninfo = sizeof PGSQL_CONNECT_FMTSTRING +
        strlen(escaped_server) + (size_t) 5U + strlen(escaped_db) + 
        strlen(escaped_user) + strlen(escaped_pw);
    if ((conninfo = malloc(sizeof_conninfo)) == NULL) {
			rprintf(FLOG,"ERR malloc(sizeof_conninfo)\n");
        goto bye;
    }
    if (SNCHECK(snprintf(conninfo, sizeof_conninfo,
                         PGSQL_CONNECT_FMTSTRING, 
                         server, port, db, user, pw), sizeof_conninfo)) {
			rprintf(FLOG,"ERR SNCHECK()\n");
        goto bye;
    }    
	//rprintf(FLOG,"ERR conninfo:%s\n",conninfo);
     if ((*id_sql_server = PQconnectdb(conninfo)) == NULL ||
        PQstatus(*id_sql_server) == CONNECTION_BAD) {
        free(conninfo);
    if (server_down == 0) {
        server_down++;
        //logfile(LOG_ERR, MSG_SQL_DOWN);
    }
			rprintf(FLOG,"ERR PQconnectdb\n");
        goto bye;
    }
    server_down = 0;
    ret = 0;
    
    bye:
    free(conninfo);
    free(escaped_server);
    free(escaped_db);
    free(escaped_user);
    free(escaped_pw);

    return ret;
}

int pw_pgsql_simplequery(PGconn * const id_sql_server,
                                const char * const query)
{
    PGresult *result;

    if ((result = PQexec(id_sql_server, query)) == NULL) {
        return -1;
    }
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        PQclear(result);        
    return -1;
    }
    PQclear(result);
    
    return 0;
}

char *pw_pgsql_getquery(PGconn * const id_sql_server,
                               const char * const orig_query,
                               const char * const account,
                               const char * const ip,
                               const char * const port,
                               const char * const peer_ip,
                               const char * const decimal_ip)
{
    PGresult *qresult = NULL;
    size_t length;
    char *answer = NULL;
    char query[PGSQL_MAX_REQUEST_LENGTH];

    if (orig_query == NULL || *orig_query == 0) {
 		rprintf(FLOG,"ERR1\n");
        goto bye;
    }
    if (sqlsubst(orig_query, query, sizeof query,
                 account, ip, port, peer_ip, decimal_ip) == NULL) {
 		rprintf(FLOG,"ERR2\n");
        goto bye;
    }
    if ((qresult = PQexec(id_sql_server, query)) == NULL) {
        //logfile(LOG_WARNING, MSG_SQL_WRONG_PARMS " : [%s]", query);        
 		rprintf(FLOG,"MSG_SQL_WRONG_PARMS : [%s]\n", query);
       goto bye;
    }
    if (PQresultStatus(qresult) != PGRES_TUPLES_OK ||
        PQnfields(qresult) != 1 ||
        PQntuples(qresult) != 1 ||
        PQgetisnull(qresult, 0, 0)) {
 		rprintf(FLOG,"ERR Multiples\n");
        goto bye;
    }
    if ((length = (size_t) PQgetlength(qresult, 0, 0) + (size_t) 1U)
        <= (size_t) 1U || (answer = malloc(length)) == NULL) {
 		rprintf(FLOG,"ERR4\n");
        goto bye;
    }
    strncpy(answer, PQgetvalue(qresult, 0, 0), length - (size_t) 1U);
    answer[length - (size_t) 1U] = 0;
    
    bye:
    if (qresult != NULL) {
        PQclear(qresult);
    }
    
    return answer;    
}

void pw_pgsql_check(AuthResult * const result,
                    const char *account, const char *password,
                    const struct sockaddr_storage * const sa,
                    const struct sockaddr_storage * const peer)
{
    PGconn *id_sql_server = NULL;
    const char *spwd = NULL;           /* stored password */
    const char *uid = sql_default_uid; /* stored system login/uid */
    const char *gid = sql_default_gid; /* stored system group/gid */
    const char *dir = NULL;            /* stored home directory */
#ifdef QUOTAS
    const char *sqta_fs = NULL;        /* stored quota files */    
    const char *sqta_sz = NULL;        /* stored quota size */
#endif    
#ifdef RATIOS
    const char *ratio_ul = NULL;       /* stored ratio UL */
    const char *ratio_dl = NULL;       /* stored ratio DL */
#endif    
#ifdef THROTTLING
    const char *bandwidth_ul = NULL;   /* stored bandwidth UL */
    const char *bandwidth_dl = NULL;   /* stored bandwidth DL */
#endif
    char *escaped_account = NULL;
    char *escaped_ip = NULL;
    char *escaped_port = NULL;
    char *escaped_peer_ip = NULL;
    char *escaped_decimal_ip = NULL;    
    char *scrambled_password = NULL;
    int committed = 1;
    int crypto_crypt = 0, crypto_plain = 0, crypto_md5 = 0, crypto_md5sha1 = 0; /* TRICK */
    unsigned long decimal_ip_num = 0UL;
    char decimal_ip[42];
    char hbuf[NI_MAXHOST];
    char pbuf[NI_MAXSERV];
    char phbuf[NI_MAXHOST];
    
    result->auth_ok = 0;
    if (pw_pgsql_validate_name(account) != 0) {
        goto bye;
    }
    if (getnameinfo((const struct sockaddr *) sa, STORAGE_LEN(*sa),
                    hbuf, sizeof hbuf, pbuf, sizeof pbuf,
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0 ||
        getnameinfo((const struct sockaddr *) peer, STORAGE_LEN(*peer),
                    phbuf, sizeof phbuf, NULL, (size_t) 0U,
                    NI_NUMERICHOST) != 0) {
        goto bye;
    }
    *decimal_ip = 0;
    //if (STORAGE_FAMILY(*peer) == AF_INET) {
        const unsigned char *decimal_ip_raw =
            (const unsigned char *) &(STORAGE_SIN_ADDR(*peer));
        decimal_ip_num = (decimal_ip_raw[0] << 24) | 
            (decimal_ip_raw[1] << 16) | (decimal_ip_raw[2] << 8) |
            decimal_ip_raw[3];
        if (SNCHECK(snprintf(decimal_ip, sizeof decimal_ip,
                             "%lu", decimal_ip_num), sizeof decimal_ip)) {
            goto bye;
        }
    //}
    if (pw_pgsql_connect(&id_sql_server) != 0) {
        goto bye;
    }
    if ((escaped_account = 
         pw_pgsql_escape_string(account)) == NULL) {
        goto bye;
    }
    if ((escaped_ip = 
         pw_pgsql_escape_string(hbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_port = 
         pw_pgsql_escape_string(pbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_peer_ip = 
         pw_pgsql_escape_string(phbuf)) == NULL) {
        goto bye;
    }
    if ((escaped_decimal_ip = 
         pw_pgsql_escape_string(decimal_ip)) == NULL) {
        goto bye;
    }
    if (pw_pgsql_simplequery(id_sql_server, PGSQL_TRANSACTION_START) == 0) {
        committed = 0;
    }
    /*logfile(LOG_WARNING, "START AUTH 2 [%s]", sqlreq_getpw); */
    if ((spwd = pw_pgsql_getquery(id_sql_server, sqlreq_getpw,
                                  escaped_account, escaped_ip,
                                  escaped_port, escaped_peer_ip,
                                  escaped_decimal_ip)) == NULL) {
        goto bye;
    }
    /*logfile(LOG_WARNING, "START AUTH 3 [%s]", sqlreq_getuid);*/
    if (uid == NULL) {
        uid = pw_pgsql_getquery(id_sql_server, sqlreq_getuid,
                                escaped_account, escaped_ip, 
                                escaped_port, escaped_peer_ip,
                                escaped_decimal_ip);
    }
    if (uid == NULL) {
        goto bye;
    }
    /*logfile(LOG_WARNING, "START AUTH 4 [%s]", sqlreq_getgid);*/
    if (gid == NULL) {
        gid = pw_pgsql_getquery(id_sql_server, sqlreq_getgid,
                                escaped_account, escaped_ip,
                                escaped_port, escaped_peer_ip,
                                escaped_decimal_ip);
    }
    if (gid == NULL) {
        goto bye;
    }
    /*logfile(LOG_WARNING, "START AUTH 5 [%s]", sqlreq_getdir);*/
    if ((dir = pw_pgsql_getquery(id_sql_server, sqlreq_getdir,
                                 escaped_account, escaped_ip,
                                 escaped_port, escaped_peer_ip,
                                 escaped_decimal_ip)) == NULL) {
        goto bye;
    }
    result->auth_ok--;                  /* -1 */
    if (strcasecmp(crypto, PASSWD_SQL_ANY) == 0) {
        crypto_crypt++;
        crypto_md5++;
    } else if (strcasecmp(crypto, PASSWD_SQL_CRYPT) == 0) {
        crypto_crypt++;
    } else if (strcasecmp(crypto, PASSWD_SQL_MD5) == 0) {
        crypto_md5++;
    } else if (strcasecmp(crypto, PASSWD_SQL_MD5SHA1) == 0) {
        crypto_md5sha1++;	/* TRICK */
    } else {                           /* default to plaintext */
        crypto_plain++;
    }
    if (crypto_crypt != 0) {
        register const char *crypted;
        
        if ((crypted = (const char *) crypt(password, spwd)) != NULL &&
            strcmp(crypted, spwd) == 0) {
            goto auth_ok;
        }
    }
    if (crypto_md5 != 0) {
        register const char *crypted;
        
        if ((crypted = (const char *) crypto_hash_md5(password, 1)) != NULL &&
            strcmp(crypted, spwd) == 0) {
            goto auth_ok;
        }
    }
    if (crypto_md5sha1 != 0) { /* TRICK */
        register const char *crypted;
        
        if ((crypted = (const char *) crypto_hash_sha1(password, 1)) != NULL ) {
            if ((crypted = (const char *) crypto_hash_md5(crypted, 1)) != NULL &&
                strcmp(crypted, spwd) == 0) {
                goto auth_ok;
            }
        }
    }
    if (crypto_plain != 0) {
        if (*password != 0 &&    /* refuse null cleartext passwords */
            strcmp(password, spwd) == 0) {
            goto auth_ok;
        }
    }
    goto bye;
    
    auth_ok:
    /*
     * do *NOT* accept root uid/gid - if the database is compromized, the FTP
     * server could also be rooted.
     */
    result->uid = (uid_t) strtoul(uid, NULL, 10);
    if (result->uid <= (uid_t) 0) {
        struct passwd *pw;
        
        if ((pw = getpwnam(uid)) == NULL || pw->pw_uid <= (uid_t) 0) {
            goto bye;
        }
        result->uid = pw->pw_uid;
    }
    result->gid = (gid_t) strtoul(gid, NULL, 10);
    if (result->gid <= (gid_t) 0) {
        struct group *gr;
        
        if ((gr = getgrnam(gid)) == NULL || gr->gr_gid <= (gid_t) 0) {
            goto bye;
        }
        result->gid = gr->gr_gid;
    }    
    result->dir = dir;
    dir = NULL;    
#ifdef QUOTAS
    if ((sqta_fs = pw_pgsql_getquery(id_sql_server, sqlreq_getqta_fs,
                                     escaped_account, escaped_ip,
                                     escaped_port, escaped_peer_ip,
                                     escaped_decimal_ip)) != NULL) {
        const unsigned long long q = strtoull(sqta_fs, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_files = q;
            result->quota_files_changed = 1;
        }
    }
    if ((sqta_sz = pw_pgsql_getquery(id_sql_server, sqlreq_getqta_sz,
                                     escaped_account, escaped_ip,
                                     escaped_port, escaped_peer_ip,
                                     escaped_decimal_ip)) != NULL) {
        const unsigned long long q = strtoull(sqta_sz, NULL, 10);
        
        if (q > 0ULL) {
            result->user_quota_size = q * (1024UL * 1024UL);
            result->quota_size_changed = 1;
        }
    }
#endif           
#ifdef RATIOS
    if ((ratio_ul = pw_pgsql_getquery(id_sql_server, sqlreq_getratio_ul,
                                      escaped_account, escaped_ip,
                                      escaped_port, escaped_peer_ip,
                                      escaped_decimal_ip)) != NULL) {
        const unsigned int q = (unsigned int) strtoul(ratio_ul, NULL, 10);
        
        if (q > 0U) {
            result->ratio_upload = q;
            result->ratio_ul_changed = 1;
        }
    }
    if ((ratio_dl = pw_pgsql_getquery(id_sql_server, sqlreq_getratio_dl,
                                      escaped_account, escaped_ip,
                                      escaped_port, escaped_peer_ip,
                                      escaped_decimal_ip)) != NULL) {
        const unsigned int q = (unsigned int) strtoul(ratio_dl, NULL, 10);
        
        if (q > 0U) {
            result->ratio_download = q;
            result->ratio_dl_changed = 1;
        }
    }
#endif
#ifdef THROTTLING
    if ((bandwidth_ul = pw_pgsql_getquery(id_sql_server, sqlreq_getbandwidth_ul,
                                          escaped_account, escaped_ip,
                                          escaped_port, escaped_peer_ip,
                                          escaped_decimal_ip)) != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_ul, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_ul = q * 1024UL;
            result->throttling_ul_changed = 1;
        }
    }
    if ((bandwidth_dl = pw_pgsql_getquery(id_sql_server, sqlreq_getbandwidth_dl,
                                          escaped_account, escaped_ip,
                                          escaped_port, escaped_peer_ip,
                                          escaped_decimal_ip)) != NULL) {
        const unsigned long q = (unsigned long) strtoul(bandwidth_dl, NULL, 10);
        
        if (q > 0UL) {
            result->throttling_bandwidth_dl = q * 1024UL;
            result->throttling_dl_changed = 1;
        }
    }
#endif    
    result->slow_tilde_expansion = 1;
    result->auth_ok =- result->auth_ok;
    bye:
    if (committed == 0) {
        (void) pw_pgsql_simplequery(id_sql_server, PGSQL_TRANSACTION_END);
    }
    if (id_sql_server != NULL) {
        PQfinish(id_sql_server);
    }
    if (spwd != NULL) {
        free((void *) spwd);
    }
    if (uid != NULL) {
        free((void *) uid);
    }
    if (gid != NULL) {
        free((void *) gid);
    }
    if (dir != NULL) {
        free((void *) dir);
    }
    if (scrambled_password != NULL) {
        free(scrambled_password);
    }
#ifdef QUOTAS
    if (sqta_fs != NULL) {
        free((void *) sqta_fs);
    }
    if (sqta_sz != NULL) {
        free((void *) sqta_sz);
    }
#endif    
#ifdef RATIOS
    if (ratio_ul != NULL) {
        free((void *) ratio_ul);
    }
    if (ratio_dl != NULL) {
        free((void *) ratio_dl);
    }
#endif    
#ifdef THROTTLING
    if (bandwidth_ul != NULL) {
        free((void *) bandwidth_ul);
    }
    if (bandwidth_dl != NULL) {
        free((void *) bandwidth_dl);
    }
#endif    
    if (escaped_account != NULL) {
        free((void *) escaped_account);
    }
    if (escaped_ip != NULL) {
        free((void *) escaped_ip);
    }
    if (escaped_port != NULL) {
        free((void *) escaped_port);
    }
    if (escaped_peer_ip != NULL) {
        free((void *) escaped_peer_ip);
    }
    if (escaped_decimal_ip != NULL) {
        free((void *) escaped_decimal_ip);
    }    
}

void pw_pgsql_parse(const char * const file)
{
    if (generic_parser(file, pgsql_config_keywords) != 0) {
        //die(421, LOG_ERR, MSG_CONF_ERR ": " MSG_ILLEGAL_CONFIG_FILE_SQL ": %s" , file);
	exit(0);
    }    
    if (server == NULL ) {
        //die(421, LOG_ERR, MSG_SQL_MISSING_SERVER);        
	exit(0);
    }
    if (port_s != NULL) {
        port = atoi(port_s);
        if (port <= 0 || port > 65535) {
            port = PGSQL_DEFAULT_PORT;
        }
        free(port_s);
        port_s = NULL;
    }
}

#define ZFREE(X) if ((X) != NULL) { free(X); (X) = NULL; }

void pw_pgsql_exit(void)
{
    ZFREE(server);
    ZFREE(port_s);
    port = -1;    
    ZFREE(user);
    ZFREE(pw);
    ZFREE(db);
    ZFREE(crypto);
    ZFREE(sqlreq_getpw);
    ZFREE(sqlreq_getuid);
    ZFREE(sql_default_uid);
    ZFREE(sqlreq_getgid);
    ZFREE(sql_default_gid);
    ZFREE(sqlreq_getdir);
#ifdef QUOTAS
    ZFREE(sqlreq_getqta_fs);
    ZFREE(sqlreq_getqta_sz);
#endif
#ifdef RATIOS
    ZFREE(sqlreq_getratio_ul);
    ZFREE(sqlreq_getratio_dl);    
#endif
#ifdef THROTTLING
    ZFREE(sqlreq_getbandwidth_ul);
    ZFREE(sqlreq_getbandwidth_dl);    
#endif
}

extern signed char v6ready;


int workaround_snprintf(char *str, size_t size, const char *format, ...)
{
    int v;
    int r = 0;
    
    va_list va;    
    va_start(va, format);    
    v = vsnprintf(str, size, format, va);
    if (v < 0 || (ssize_t) v >= (ssize_t) size) {
        r--;
    }
    va_end(va);

    return r;
}


//#endif
