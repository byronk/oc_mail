#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>

static void oc_smtp_init_session(ngx_connection_t *c);
static void oc_smtp_greeting(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_create_buffer(oc_smtp_session_t *s, ngx_connection_t *c);

void oc_smtp_init_protocol(ngx_event_t *rev);


static ngx_str_t  smtp_internal_server_error = 
	ngx_string("451 4.3.2 Internal server error" CRLF);
static ngx_str_t  smtp_unavailable = ngx_string("[UNAVAILABLE]");

/*
static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
static u_char  smtp_invalid_pipelining[] =
   "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
*/


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

#if (OC_SMTP_SSL)
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
	oc_smtp_session_t        *s;

	s = c->data;

	s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * oc_smtp_max_module);
	if (s->ctx == NULL) {
		oc_smtp_session_internal_server_error(s);
		return;
	}

	c->write->handler = oc_smtp_send;

	s->host = smtp_unavailable;
	oc_smtp_greeting(s, c);
	
	return;

}


u_char *
oc_smtp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
	u_char              *p;
	oc_smtp_session_t  *s;
	oc_smtp_log_ctx_t  *ctx;

	if (log->action) {
		p = ngx_snprintf(buf, len, " while %s", log->action);
		len -= p - buf;
		buf = p;
	}

	ctx = log->data;

	p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
	len -= p - buf;
	buf = p;

	s = ctx->session;

	if (s == NULL) {
		return p;
	}

	p = ngx_snprintf(buf, len, "%s, server: %V",
				s->starttls ? " using starttls" : "",
				s->addr_text);
	len -= p - buf;
	buf = p;

	if (s->login.len == 0) {
		return p;
	}

	p = ngx_snprintf(buf, len, ", login: \"%V\"", &s->login);
	len -= p - buf;
	buf = p;

	return p;
}

void
oc_smtp_send(ngx_event_t *wev)
{
	ngx_int_t                  n;
	ngx_connection_t          *c;
	oc_smtp_session_t        *s;
	oc_smtp_core_srv_conf_t  *cscf;

	c = wev->data;
	s = c->data;

	if (wev->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
		c->timedout = 1;
		oc_smtp_close_connection(c);
		return;
	}

	if (s->out.len == 0) {
		if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
			oc_smtp_close_connection(c);
		}

		return;
	}

	n = c->send(c, s->out.data, s->out.len);

	if (n > 0) {
		s->out.len -= n;

		if (wev->timer_set) {
			ngx_del_timer(wev);
		}

		if (s->quit) {
			oc_smtp_close_connection(c);
			return;
		}

		if (s->blocked) {
			c->read->handler(c->read);
		}

		return;
	}

	if (n == NGX_ERROR) {
		oc_smtp_close_connection(c);
		return;
	}

	/* n == NGX_AGAIN */

	cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

	ngx_add_timer(c->write, cscf->timeout);

	if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
		oc_smtp_close_connection(c);
		return;
	}
}

void
oc_smtp_session_internal_server_error(oc_smtp_session_t *s)
{
	s->out = smtp_internal_server_error;
	s->quit = 1;

	oc_smtp_send(s->connection->write);
}

static void
oc_smtp_greeting(oc_smtp_session_t *s, ngx_connection_t *c)
{
    ngx_msec_t                 timeout;
    oc_smtp_core_srv_conf_t  *cscf;

    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
                   "smtp greeting for \"%V\"", &s->host);

    cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);
    //sscf = oc_smtp_get_module_srv_conf(s, oc_smtp_smtp_module);

    timeout = cscf->timeout;
    ngx_add_timer(c->read, timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        oc_smtp_close_connection(c);
    }

    c->read->handler = oc_smtp_init_protocol;

    s->out = cscf->greeting;

	//测试用途，完成greeting后就关闭连接
	s->quit = 1;

    oc_smtp_send(c->write);
}



void
oc_smtp_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    oc_smtp_session_t  *s;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        oc_smtp_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (oc_smtp_create_buffer(s, c) != NGX_OK) {
            return;
        }
    }

    //s->mail_state = ngx_smtp_start;
    //c->read->handler = oc_smtp_auth_state;

    //oc_smtp_auth_state(rev);
}



static ngx_int_t
oc_smtp_create_buffer(oc_smtp_session_t *s, ngx_connection_t *c)
{
    oc_smtp_core_srv_conf_t  *cscf;

    if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t)) == NGX_ERROR) {
        oc_smtp_session_internal_server_error(s);
        return NGX_ERROR;
    }

    cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

    s->buffer = ngx_create_temp_buf(c->pool, cscf->client_buffer_size);
    if (s->buffer == NULL) {
        oc_smtp_session_internal_server_error(s);
        return NGX_ERROR;
    }

    return NGX_OK;
}

