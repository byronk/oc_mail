#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>

static void oc_smtp_init_session(ngx_connection_t *c);



void
oc_smtp_close_connection(ngx_connection_t *c)
{
	ngx_pool_t  *pool;

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"close mail connection: %d", c->fd);

#if (oc_smtp_SSL)

	if (c->ssl) {
		if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
			c->ssl->handler = oc_smtp_close_connection;
			return;
		}
	}

#endif

#if (NGX_STAT_STUB)
	(void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

	c->destroyed = 1;

	pool = c->pool;

	ngx_close_connection(c);

	ngx_destroy_pool(pool);
}



void
oc_smtp_init_connection(ngx_connection_t *c)
{
	ngx_uint_t             i;
	oc_smtp_port_t       *port;
	struct sockaddr       *sa;
	struct sockaddr_in    *sin;
	oc_smtp_log_ctx_t    *ctx;
	oc_smtp_in_addr_t    *addr;
	oc_smtp_session_t    *s;
	oc_smtp_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6   *sin6;
	oc_smtp_in6_addr_t   *addr6;
#endif


	/* find the server configuration for the address:port */

	/* AF_INET only */

	port = c->listening->servers;

	if (port->naddrs > 1) {

		/*
		   * There are several addresses on this port and one of them
		   * is the "*:port" wildcard so getsockname() is needed to determine
		   * the server address.
		   *
		   * AcceptEx() already gave this address.
		   */

		if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
			oc_smtp_close_connection(c);
			return;
		}

		sa = c->local_sockaddr;

		switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
			case AF_INET6:
				sin6 = (struct sockaddr_in6 *) sa;

				addr6 = port->addrs;

				/* the last address is "*" */

				for (i = 0; i < port->naddrs - 1; i++) {
					if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
						break;
					}
				}

				addr_conf = &addr6[i].conf;

				break;
#endif

			default: /* AF_INET */
				sin = (struct sockaddr_in *) sa;

				addr = port->addrs;

				/* the last address is "*" */

				for (i = 0; i < port->naddrs - 1; i++) {
					if (addr[i].addr == sin->sin_addr.s_addr) {
						break;
					}
				}

				addr_conf = &addr[i].conf;

				break;
		}

	} else {
		switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
			case AF_INET6:
				addr6 = port->addrs;
				addr_conf = &addr6[0].conf;
				break;
#endif

			default: /* AF_INET */
				addr = port->addrs;
				addr_conf = &addr[0].conf;
				break;
		}
	}

	s = ngx_pcalloc(c->pool, sizeof(oc_smtp_session_t));
	if (s == NULL) {
		oc_smtp_close_connection(c);
		return;
	}

	s->main_conf = addr_conf->ctx->main_conf;
	s->srv_conf = addr_conf->ctx->srv_conf;

	s->addr_text = &addr_conf->addr_text;

	c->data = s;
	s->connection = c;

	ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
				c->number, &c->addr_text, s->addr_text);

	ctx = ngx_palloc(c->pool, sizeof(oc_smtp_log_ctx_t));
	if (ctx == NULL) {
		oc_smtp_close_connection(c);
		return;
	}

	ctx->client = &c->addr_text;
	ctx->session = s;

	c->log->connection = c->number;
	c->log->handler = oc_smtp_log_error;
	c->log->data = ctx;
	c->log->action = "sending client greeting line";

	c->log_error = NGX_ERROR_INFO;

#if (oc_smtp_SSL)
	{
		oc_smtp_ssl_conf_t  *sslcf;

		sslcf = oc_smtp_get_module_srv_conf(s, oc_smtp_ssl_module);

		if (sslcf->enable) {
			c->log->action = "SSL handshaking";

			oc_smtp_ssl_init_connection(&sslcf->ssl, c);
			return;
		}

		if (addr_conf->ssl) {

			c->log->action = "SSL handshaking";

			if (sslcf->ssl.ctx == NULL) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
							"no \"ssl_certificate\" is defined "
							"in server listening on SSL port");
				oc_smtp_close_connection(c);
				return;
			}

			oc_smtp_ssl_init_connection(&sslcf->ssl, c);
			return;
		}

	}
#endif

	oc_smtp_init_session(c);
}

static void
oc_smtp_init_session(ngx_connection_t *c)
{
}
