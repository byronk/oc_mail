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
#if (NGX_MAIL_SSL)
	unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
	unsigned                ipv6only:2;
#endif
} oc_smtp_listen_t;

typedef struct {
	ngx_array_t             servers;     /* oc_smtp_core_srv_conf_t */
	ngx_array_t             listen;      /* oc_smtp_listen_t */
} oc_smtp_core_main_conf_t;

typedef struct {
	ngx_array_t             servers;     /* oc_smtp_core_srv_conf_t */
	ngx_array_t             listen;      /* oc_smtp_listen_t */
} oc_smtp_core_main_conf_t;


typedef struct {
	ngx_msec_t              timeout;
	ngx_msec_t              resolver_timeout;
	ngx_flag_t              so_keepalive;
	ngx_str_t               server_name;
	/* server ctx */
	oc_smtp_conf_ctx_t    *ctx;
} oc_smtp_core_srv_conf_t;


typedef struct {
	void                  **ctx;
	void                  **main_conf;
	void                  **srv_conf;
}  oc_smtp_session_t;

#define OC_SMTP_MODULE         0x6C69616D    /* SMTP */

#define OC_SMTP_MAIN_CONF      0x02000000
#define OC_SMTP_SRV_CONF       0x04000000

#define OC_SMTP_MAIN_CONF_OFFSET  offsetof(oc_smtp_conf_ctx_t, main_conf)
#define OC_SMTP_SRV_CONF_OFFSET   offsetof(oc_smtp_conf_ctx_t, srv_conf)

typedef struct {
	void	*(*create_main_conf)(ngx_conf_t *cf);
	char    *(*init_main_conf)(ngx_conf_t *cf, void *conf);

	void    *(*create_srv_conf)(ngx_conf_t *cf);
	char    *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} oc_smtp_module_t;




#endif
