/***************************************************************************
 *   sslscan - A SSL cipher scanning tool                                  *
 *   Copyright 2007-2009 by Ian Ventura-Whiting (Fizz)                     *
 *   fizz@titania.co.uk                                                    *
 *   Copyright 2010 by Michael Boman (michael@michaelboman.org)            *
 *   Copyleft 2010 by Jacob Appelbaum <jacob@appelbaum.net>                *
 *   Copyleft 2013 by rbsec <robin@rbsec.net>                              *
 *   Copyleft 2014 by Julian Kornberger <jk+github@digineo.de>             *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *   In addition, as a special exception, the copyright holders give       *
 *   permission to link the code of portions of this program with the      *
 *   OpenSSL library under certain conditions as described in each         *
 *   individual source file, and distribute linked combinations            *
 *   including the two.                                                    *
 *   You must obey the GNU General Public License in all respects          *
 *   for all of the code used other than OpenSSL.  If you modify           *
 *   file(s) with this exception, you may extend this exception to your    *
 *   version of the file(s), but you are not obligated to do so.  If you   *
 *   do not wish to do so, delete this exception statement from your       *
 *   version.  If you delete this exception statement from all source      *
 *   files in the program, then also delete it here.                       *
 ***************************************************************************/

#ifndef HAVE_SSLSCAN_H_
#define HAVE_SSLSCAN_H_

// Defines...
#define false 0
#define true 1

#define mode_help 0
#define mode_version 1
#define mode_single 2
#define mode_multiple 3

#define BUFFERSIZE 1024

#define ssl_all 0
#define ssl_v2 1
#define ssl_v3 2
#define tls_all 3
#define tls_v10 4
#define tls_v11 5
#define tls_v12 6

#define CLIENT_MYSQL                1
#define CLIENT_FOUND_ROWS	    2	/* Found instead of affected rows */
#define CLIENT_LONG_FLAG	    4	/* Get all column flags */
#define CLIENT_CONNECT_WITH_DB	    8	/* One can specify db on connect */
#define CLIENT_NO_SCHEMA	   16	/* Don't allow database.table.column */
#define CLIENT_COMPRESS		   32	/* Can use compression protocol */
#define CLIENT_ODBC		   64	/* Odbc client */
#define CLIENT_LOCAL_FILES	  128	/* Can use LOAD DATA LOCAL */
#define CLIENT_IGNORE_SPACE	  256	/* Ignore spaces before '(' */
#define CLIENT_INTERACTIVE	  1024	/* This is an interactive client */
#define CLIENT_SSL                2048     /* Switch to SSL after handshake */
#define CLIENT_IGNORE_SIGPIPE     4096     /* IGNORE sigpipes */
#define CLIENT_TRANSACTIONS	  8192	/* Client knows about transactions */
/* added in 4.x */
#define CLIENT_PROTOCOL_41         512
#define CLIENT_RESERVED          16384
#define CLIENT_SECURE_CONNECTION 32768  
#define CLIENT_MULTI_STATEMENTS  (1UL << 16)
#define CLIENT_MULTI_RESULTS     (1UL << 17)
#define CLIENT_PS_MULTI_RESULTS  (1UL << 18)
#define CLIENT_PLUGIN_AUTH       (1UL << 19)
#define CLIENT_CONNECT_ATTRS     (1UL << 20)
#define CLIENT_PROGRESS          (1UL << 29) /* client supports progress indicator */
#define CLIENT_SSL_VERIFY_SERVER_CERT (1UL << 30)
#define CLIENT_REMEMBER_OPTIONS  (1UL << 31)

/* MariaDB specific capabilities */
#define MARIADB_CLIENT_FLAGS 0xFFFFFFFF00000000ULL
#define MARIADB_CLIENT_PROGRESS (1ULL << 32)
#define MARIADB_CLIENT_COM_MULTI (1ULL << 33)
//#define MARIADB_CLIENT_EXTENDED_FLAGS (1ULL << 63)

#define int3store(T,A)  do { *(T)=  (unsigned char) ((A));\
                            *(T+1)=(unsigned char) (((unsigned int) (A) >> 8));\
                            *(T+2)=(unsigned char) (((A) >> 16)); } while (0)
#define MARIADB_CLIENT_SUPPORTED_FLAGS (MARIADB_CLIENT_PROGRESS |\
                                       MARIADB_CLIENT_COM_MULTI)

#define CLIENT_SUPPORTED_FLAGS  (CLIENT_MYSQL |\
                                 CLIENT_FOUND_ROWS |\
                                 CLIENT_LONG_FLAG |\
                                 CLIENT_CONNECT_WITH_DB |\
                                 CLIENT_NO_SCHEMA |\
                                 CLIENT_COMPRESS |\
                                 CLIENT_ODBC |\
                                 CLIENT_LOCAL_FILES |\
                                 CLIENT_IGNORE_SPACE |\
                                 CLIENT_INTERACTIVE |\
                                 CLIENT_SSL |\
                                 CLIENT_IGNORE_SIGPIPE |\
                                 CLIENT_TRANSACTIONS |\
                                 CLIENT_PROTOCOL_41 |\
                                 CLIENT_RESERVED |\
                                 CLIENT_SECURE_CONNECTION |\
                                 CLIENT_MULTI_STATEMENTS |\
                                 CLIENT_MULTI_RESULTS |\
                                 CLIENT_PROGRESS |\
		                 CLIENT_SSL_VERIFY_SERVER_CERT |\
                                 CLIENT_REMEMBER_OPTIONS |\
                                 CLIENT_CONNECT_ATTRS)

#define CLIENT_CAPABILITIES	(CLIENT_MYSQL | \
                                 CLIENT_LONG_FLAG |\
                                 CLIENT_TRANSACTIONS |\
                                 CLIENT_SECURE_CONNECTION |\
                                 CLIENT_MULTI_RESULTS | \
                                 CLIENT_PS_MULTI_RESULTS |\
                                 CLIENT_PROTOCOL_41 |\
                                 CLIENT_PLUGIN_AUTH |\
                                 CLIENT_CONNECT_ATTRS)

#define CLIENT_DEFAULT_FLAGS ((CLIENT_SUPPORTED_FLAGS & ~CLIENT_COMPRESS)\
                                                      & ~CLIENT_SSL)


// Macros for various outputs
#define printf_error(format, ...)   fprintf(stderr, format, ##__VA_ARGS__)
#define printf_xml(format, ...)     if (options->xmlOutput) fprintf(options->xmlOutput, format, ##__VA_ARGS__)
#define printf_verbose(format, ...) if (options->verbose) printf(format, ##__VA_ARGS__)

// Colour Console Output...
#if !defined(_WIN32)
// Always better to do "const char RESET[] = " because it saves relocation records.
const char *RESET = "[0m";            // DEFAULT
const char *COL_RED = "[31m";
const char *COL_YELLOW = "[33m";
const char *COL_BLUE = "[1;34m";
const char *COL_GREEN = "[32m";
const char *COL_PURPLE = "[35m";
const char *COL_RED_BG = "[41m";
#else
const char *RESET = "";
const char *COL_RED = "";
const char *COL_YELLOW = "";
const char *COL_BLUE = "";
const char *COL_GREEN = "";
const char *COL_PURPLE = "";
const char *COL_RED_BG = "";
#endif

#ifdef _WIN32
    #define SLEEPMS(ms) Sleep(ms);
#else
    #define SLEEPMS(ms) do {                    \
        struct timeval wait = { 0, ms*1000 };   \
        select(0, NULL, NULL, NULL, &wait);     \
    } while(0)
#endif

const char *program_banner = "                   _\n"
                             "           ___ ___| |___  ___ __ _ _ __\n"
                             "          / __/ __| / __|/ __/ _` | '_ \\\n"
                             "          \\__ \\__ \\ \\__ \\ (_| (_| | | | |\n"
                             "          |___/___/_|___/\\___\\__,_|_| |_|\n\n";

struct sslCipher
{
    // Cipher Properties...
    const char *name;
    char *version;
    int bits;
    char description[512];
    const SSL_METHOD *sslMethod;
    struct sslCipher *next;
};

struct sslCheckOptions
{
    // Program Options...
    char host[512];
    int port;
    int showCertificate;
    int checkCertificate;
    int showTrustedCAs;
    int showClientCiphers;
    int showCipherIds;
    int ciphersuites;
    int reneg;
    int compression;
    int heartbleed;
    int starttls_ftp;
    int starttls_imap;
    int starttls_irc;
    int starttls_pop3;
    int starttls_smtp;
    int starttls_xmpp;
    int xmpp_server;
    int sslVersion;
    int targets;
    int sslbugs;
    int http;
    int rdp;
    int verbose;
    int cipher_details;
    int ipv4;
    int ipv6;
    int ocspStatus;
    char cipherstring[65536];

    // File Handles...
    FILE *xmlOutput;

    // TCP Connection Variables...
    short h_addrtype;
    struct sockaddr_in serverAddress;
    struct sockaddr_in6 serverAddress6;
    struct timeval timeout;
    unsigned int sleep;

    // SSL Variables...
    SSL_CTX *ctx;
    struct sslCipher *ciphers;
    char *clientCertsFile;
    char *privateKeyFile;
    char *privateKeyPassword;
    int testMariaDB;
};

// store renegotiation test data
struct renegotiationOutput
{
    int supported;
    int secure;
};

/* We redefine these so that we can run correctly even if the vendor gives us
 * a version of OpenSSL that does not match its header files.  (Apple: I am
 * looking at you.)
 */
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#    define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x00040000L
#endif
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#    define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x0010
#endif

// Utilities
int fileExists(char *);
void readLine(FILE *, char *, int);
ssize_t sendString(int, const char[]);
int readOrLogAndClose(int, void *, size_t, const struct sslCheckOptions *);
const char *printableSslMethod(const SSL_METHOD *);
static int password_callback(char *, int, int, void *);
int ssl_print_tmp_key(struct sslCheckOptions *, SSL *s);
static int ocsp_resp_cb(SSL *s, void *arg);
int ocsp_certid_print(BIO *bp, OCSP_CERTID *a, int indent);

int tcpConnect(struct sslCheckOptions *);

// Tests
void tls_reneg_init(struct sslCheckOptions *);
int outputRenegotiation(struct sslCheckOptions *, struct renegotiationOutput *);
struct renegotiationOutput *newRenegotiationOutput(void);
int freeRenegotiationOutput(struct renegotiationOutput *);

int testCompression(struct sslCheckOptions *, const SSL_METHOD *);
int testRenegotiation(struct sslCheckOptions *, const SSL_METHOD *);
int testHeartbleed(struct sslCheckOptions *, const SSL_METHOD *);
int testCipher(struct sslCheckOptions *, const SSL_METHOD *);
int testProtocolCiphers(struct sslCheckOptions *, const SSL_METHOD *);
int testConnection(struct sslCheckOptions *);
int testHost(struct sslCheckOptions *);

int loadCerts(struct sslCheckOptions *);
int checkCertificateProtocols(struct sslCheckOptions *, const SSL_METHOD *);
int checkCertificate(struct sslCheckOptions *, const SSL_METHOD *);
int showCertificate(struct sslCheckOptions *);

#endif

/* vim :set ts=4 sw=4 sts=4 et : */
