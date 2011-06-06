#ifndef _OC_MAIL_H_INCLUDED_
#define _OC_MAIL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


typedef struct {
	void                  **main_conf;
	void                  **srv_conf;
} oc_mail_conf_ctx_t;


typedef struct {
	u_char                  sockaddr[NGX_SOCKADDRLEN];
	socklen_t               socklen;

	/* server ctx */
	oc_mail_conf_ctx_t      *ctx;

	unsigned                bind:1;
	unsigned                wildcard:1;
#if (NGX_MAIL_SSL)
	unsigned                ssl:1;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
	unsigned                ipv6only:2;
#endif
} oc_mail_listen_t;

typedef struct {
	void                  **ctx;
	void                  **main_conf;
	void                  **srv_conf;
}  oc_mail_session_t;

#define OC_SMTP_MODULE         0x6C69616D    /* SMTP */

typedef struct {
	void	*(*create_main_conf)(ngx_conf_t *cf);
	char    *(*init_main_conf)(ngx_conf_t *cf, void *conf);

	void    *(*create_srv_conf)(ngx_conf_t *cf);
	char    *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} oc_mail_module_t;




#endif
