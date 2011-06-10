#ifndef _OC_MAIL_H_INCLUDED_
#define _OC_MAIL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct {
	void                  **main_conf;
	void                  **srv_conf;
} oc_smtp_conf_ctx_t;


typedef struct {
	u_char                  sockaddr[NGX_SOCKADDRLEN];
	socklen_t               socklen;

	/* server ctx */
	oc_smtp_conf_ctx_t      *ctx;

	unsigned                bind:1;
	unsigned                wildcard:1;
#if (OC_SMTP_SSL)
	unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
	unsigned                ipv6only:2;
#endif
} oc_smtp_listen_t;


typedef struct {
	oc_smtp_conf_ctx_t    *ctx;
	ngx_str_t               addr_text;
#if (OC_SMTP_SSL)
	ngx_uint_t              ssl;    /* unsigned   ssl:1; */
#endif
} oc_smtp_addr_conf_t;

typedef struct {
	in_addr_t               addr;
	oc_smtp_addr_conf_t    conf;
} oc_smtp_in_addr_t;


#if (NGX_HAVE_INET6)

typedef struct {
	struct in6_addr         addr6;
	oc_smtp_addr_conf_t    conf;
} oc_smtp_in6_addr_t;

#endif


typedef struct {
	/* oc_smtp_in_addr_t or oc_smtp_in6_addr_t */
	void                   *addrs;
	ngx_uint_t              naddrs;
} oc_smtp_port_t;


typedef struct {
	int                     family;
	in_port_t               port;
	ngx_array_t             addrs;       /* array of oc_smtp_conf_addr_t */
} oc_smtp_conf_port_t;


typedef struct {
	struct sockaddr        *sockaddr;
	socklen_t               socklen;

	oc_smtp_conf_ctx_t    *ctx;

	unsigned                bind:1;
	unsigned                wildcard:1;
#if (OC_SMTP_SSL)
	unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
	unsigned                ipv6only:2;
#endif
} oc_smtp_conf_addr_t;

typedef struct {
	ngx_array_t             servers;     /* oc_smtp_core_srv_conf_t */
	ngx_array_t             listen;      /* oc_smtp_listen_t */
} oc_smtp_core_main_conf_t;

typedef struct {
	ngx_msec_t              timeout;
	ngx_msec_t              resolver_timeout;
	ngx_flag_t              so_keepalive;
	ngx_str_t               server_name;
	
	ngx_str_t               helo_server_name;
	ngx_str_t               greeting;
	size_t                  client_buffer_size;
	ngx_uint_t              auth_methods;  //存放支持的auth method，位图方式
	ngx_array_t             capabilities;  
	ngx_str_t               capability;    //存放capabilities对应的字符串
	
	/* server ctx */
	oc_smtp_conf_ctx_t    *ctx;
} oc_smtp_core_srv_conf_t;


typedef struct {
	void                  **ctx;
	void                  **main_conf;
	void                  **srv_conf;
	ngx_str_t              *addr_text;
	ngx_str_t               host;
	ngx_connection_t       *connection;

	ngx_str_t               login;
    ngx_str_t               passwd;

	ngx_str_t               out;
	ngx_buf_t              *buffer;
	ngx_uint_t              mail_state;
	ngx_array_t             args;
	ngx_uint_t              command;
	
    ngx_str_t               smtp_helo;
    ngx_str_t               smtp_from;
	ngx_array_t             smtp_rcpts;

	/* used to parse SMTP command */
    ngx_uint_t              state;
    u_char                 *cmd_start;
    u_char                 *arg_start;
    u_char                 *arg_end;
    ngx_uint_t              literal_len;

	unsigned                starttls:1;
	unsigned                quit:1;
	unsigned                blocked:1;
	unsigned                esmtp:1;
}  oc_smtp_session_t;


typedef struct {
	void	*(*create_main_conf)(ngx_conf_t *cf);
	char    *(*init_main_conf)(ngx_conf_t *cf, void *conf);

	void    *(*create_srv_conf)(ngx_conf_t *cf);
	char    *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} oc_smtp_module_t;

typedef struct {
	ngx_str_t              *client;
	oc_smtp_session_t     *session;
} oc_smtp_log_ctx_t;


typedef enum {
    oc_smtp_start = 0,
    oc_smtp_auth_login_username,
    oc_smtp_auth_login_password,
    oc_smtp_auth_plain,
    oc_smtp_auth_cram_md5,
    oc_smtp_helo,
    oc_smtp_helo_xclient,
    oc_smtp_helo_from,
    oc_smtp_xclient,
    oc_smtp_xclient_from,
    oc_smtp_xclient_helo,
    oc_smtp_from,
    oc_smtp_to
} oc_smtp_state_e;


#define OC_SMTP_MODULE         0x6C69616D    /* SMTP */

#define OC_SMTP_MAIN_CONF      0x02000000
#define OC_SMTP_SRV_CONF       0x04000000

#define OC_SMTP_AUTH_PLAIN             0
#define OC_SMTP_AUTH_LOGIN             1
#define OC_SMTP_AUTH_LOGIN_USERNAME    2
#define OC_SMTP_AUTH_APOP              3
#define OC_SMTP_AUTH_CRAM_MD5          4
#define OC_SMTP_AUTH_NONE              5

#define OC_SMTP_AUTH_PLAIN_ENABLED     0x0002
#define OC_SMTP_AUTH_LOGIN_ENABLED     0x0004
#define OC_SMTP_AUTH_APOP_ENABLED      0x0008
#define OC_SMTP_AUTH_CRAM_MD5_ENABLED  0x0010
#define OC_SMTP_AUTH_NONE_ENABLED      0x0020

#define OC_SMTP_PARSE_INVALID_COMMAND  20

#define OC_SMTP_HELO          1
#define OC_SMTP_EHLO          2
#define OC_SMTP_AUTH          3
#define OC_SMTP_QUIT          4
#define OC_SMTP_NOOP          5
#define OC_SMTP_MAIL          6
#define OC_SMTP_RSET          7
#define OC_SMTP_RCPT          8
#define OC_SMTP_DATA          9
#define OC_SMTP_VRFY          10
#define OC_SMTP_EXPN          11
#define OC_SMTP_HELP          12
#define OC_SMTP_STARTTLS      13


#define OC_SMTP_MAIN_CONF_OFFSET  offsetof(oc_smtp_conf_ctx_t, main_conf)
#define OC_SMTP_SRV_CONF_OFFSET   offsetof(oc_smtp_conf_ctx_t, srv_conf)

#define oc_smtp_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define oc_smtp_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define oc_smtp_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;

#define oc_smtp_get_module_main_conf(s, module)                             \
	(s)->main_conf[module.ctx_index]
#define oc_smtp_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]

#define oc_smtp_conf_get_module_main_conf(cf, module)                       \
	((oc_smtp_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define oc_smtp_conf_get_module_srv_conf(cf, module)                        \
	((oc_smtp_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

extern ngx_uint_t    oc_smtp_max_module;
extern ngx_module_t  oc_smtp_core_module;

void oc_smtp_init_connection(ngx_connection_t *c);
u_char *oc_smtp_log_error(ngx_log_t *log, u_char *buf, size_t len);
void oc_smtp_send(ngx_event_t *wev);
void oc_smtp_session_internal_server_error(oc_smtp_session_t *s);



#endif
