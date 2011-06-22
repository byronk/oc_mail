#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>

static void oc_smtp_init_session(ngx_connection_t *c);
static void oc_smtp_greeting(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_create_buffer(oc_smtp_session_t *s, ngx_connection_t *c);

void oc_smtp_init_protocol(ngx_event_t *rev);
void oc_smtp_auth_state(ngx_event_t *rev);

static ngx_int_t oc_smtp_cmd_helo(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_cmd_auth(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_cmd_mail(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_cmd_starttls(oc_smtp_session_t *s,
			ngx_connection_t *c);
static ngx_int_t oc_smtp_cmd_rset(oc_smtp_session_t *s, ngx_connection_t *c);
static ngx_int_t oc_smtp_cmd_rcpt(oc_smtp_session_t *s, ngx_connection_t *c);
static void oc_smtp_smtp_log_rejected_command(oc_smtp_session_t *s, ngx_connection_t *c,
			char *err);


static ngx_str_t  smtp_internal_server_error = 
	ngx_string("451 4.3.2 Internal server error" CRLF);
static ngx_str_t  smtp_unavailable = ngx_string("[UNAVAILABLE]");


static u_char  smtp_ok[] = "250 2.0.0 OK" CRLF;
static u_char  smtp_bye[] = "221 2.0.0 Bye" CRLF;
static u_char  smtp_starttls[] = "220 2.0.0 Start TLS" CRLF;
static u_char  smtp_next[] = "334 " CRLF;
static u_char  smtp_username[] = "334 VXNlcm5hbWU6" CRLF;
static u_char  smtp_password[] = "334 UGFzc3dvcmQ6" CRLF;
static u_char  smtp_invalid_command[] = "500 5.5.1 Invalid command" CRLF;
//static u_char  smtp_invalid_pipelining[] =
//   "503 5.5.0 Improper use of SMTP command pipelining" CRLF;
static u_char  smtp_invalid_argument[] = "501 5.5.4 Invalid argument" CRLF;
static u_char  smtp_auth_required[] = "530 5.7.1 Authentication required" CRLF;
static u_char  smtp_bad_sequence[] = "503 5.5.1 Bad sequence of commands" CRLF;



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

	//初始化收件人列表
	if (ngx_array_init(&s->smtp_rcpts, c->pool, 1, sizeof(ngx_str_t)) == NGX_ERROR) {
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
	//sscf = oc_smtp_get_module_srv_conf(s, oc_smtp_module);

	timeout = cscf->timeout;
	ngx_add_timer(c->read, timeout);

	if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
		oc_smtp_close_connection(c);
	}

	c->read->handler = oc_smtp_init_protocol;

	s->out = cscf->greeting;

	//测试用途，完成greeting后就关闭连接
	//s->quit = 1;

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

	s->mail_state = oc_smtp_start;
	c->read->handler = oc_smtp_auth_state;

	oc_smtp_auth_state(rev);
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



ngx_int_t
oc_smtp_parse_command(oc_smtp_session_t *s)
{
	u_char      ch, *p, *c, c0, c1, c2, c3;
	ngx_str_t  *arg;
	enum {
		sw_start = 0,
		sw_spaces_before_argument,
		sw_argument,
		sw_almost_done
	} state;

	state = s->state;

	for (p = s->buffer->pos; p < s->buffer->last; p++) {
		ch = *p;

		switch (state) {

			/* SMTP command */
			case sw_start:
				if (ch == ' ' || ch == CR || ch == LF) {
					c = s->buffer->start;

					if (p - c == 4) {

						c0 = ngx_toupper(c[0]);
						c1 = ngx_toupper(c[1]);
						c2 = ngx_toupper(c[2]);
						c3 = ngx_toupper(c[3]);

						if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'O')
						{
							s->command = OC_SMTP_HELO;

						} else if (c0 == 'E' && c1 == 'H' && c2 == 'L' && c3 == 'O')
						{
							s->command = OC_SMTP_EHLO;

						} else if (c0 == 'Q' && c1 == 'U' && c2 == 'I' && c3 == 'T')
						{
							s->command = OC_SMTP_QUIT;

						} else if (c0 == 'A' && c1 == 'U' && c2 == 'T' && c3 == 'H')
						{
							s->command = OC_SMTP_AUTH;

						} else if (c0 == 'N' && c1 == 'O' && c2 == 'O' && c3 == 'P')
						{
							s->command = OC_SMTP_NOOP;

						} else if (c0 == 'M' && c1 == 'A' && c2 == 'I' && c3 == 'L')
						{
							s->command = OC_SMTP_MAIL;

						} else if (c0 == 'R' && c1 == 'S' && c2 == 'E' && c3 == 'T')
						{
							s->command = OC_SMTP_RSET;

						} else if (c0 == 'R' && c1 == 'C' && c2 == 'P' && c3 == 'T')
						{
							s->command = OC_SMTP_RCPT;

						} else if (c0 == 'D' && c1 == 'A' && c2 == 'T' && c3 == 'A')
						{
							s->command = OC_SMTP_DATA;
							
						} else if (c0 == 'V' && c1 == 'R' && c2 == 'F' && c3 == 'Y')
						{
							s->command = OC_SMTP_VRFY;

						} else if (c0 == 'E' && c1 == 'X' && c2 == 'P' && c3 == 'N')
						{
							s->command = OC_SMTP_EXPN;

						} else if (c0 == 'H' && c1 == 'E' && c2 == 'L' && c3 == 'P')
						{
							s->command = OC_SMTP_HELP;

						} else {
							goto invalid;
						}
#if (OC_SMTP_SSL)
					} else if (p - c == 8) {

						if ((c[0] == 'S'|| c[0] == 's')
									&& (c[1] == 'T'|| c[1] == 't')
									&& (c[2] == 'A'|| c[2] == 'a')
									&& (c[3] == 'R'|| c[3] == 'r')
									&& (c[4] == 'T'|| c[4] == 't')
									&& (c[5] == 'T'|| c[5] == 't')
									&& (c[6] == 'L'|| c[6] == 'l')
									&& (c[7] == 'S'|| c[7] == 's'))
						{
							s->command = OC_SMTP_STARTTLS;

						} else {
							goto invalid;
						}
#endif
					} else {
						goto invalid;
					}

					switch (ch) {
						case ' ':
							state = sw_spaces_before_argument;
							break;
						case CR:
							state = sw_almost_done;
							break;
						case LF:
							goto done;
					}
					break;
				}

				if ((ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z')) {
					goto invalid;
				}

				break;

			case sw_spaces_before_argument:
				switch (ch) {
					case ' ':
						break;
					case CR:
						state = sw_almost_done;
						s->arg_end = p;
						break;
					case LF:
						s->arg_end = p;
						goto done;
					default:
						if (s->args.nelts <= 10) {
							state = sw_argument;
							s->arg_start = p;
							break;
						}
						goto invalid;
				}
				break;

			case sw_argument:
				switch (ch) {
					case ' ':
					case CR:
					case LF:
						arg = ngx_array_push(&s->args);
						if (arg == NULL) {
							return NGX_ERROR;
						}
						arg->len = p - s->arg_start;
						arg->data = s->arg_start;
						s->arg_start = NULL;

						switch (ch) {
							case ' ':
								state = sw_spaces_before_argument;
								break;
							case CR:
								state = sw_almost_done;
								break;
							case LF:
								goto done;
						}
						break;

					default:
						break;
				}
				break;

			case sw_almost_done:
				switch (ch) {
					case LF:
						goto done;
					default:
						goto invalid;
				}
		}
	}

	s->buffer->pos = p;
	s->state = state;

	return NGX_AGAIN;

done:

	s->buffer->pos = p + 1;

	if (s->arg_start) {
		arg = ngx_array_push(&s->args);
		if (arg == NULL) {
			return NGX_ERROR;
		}
		arg->len = s->arg_end - s->arg_start;
		arg->data = s->arg_start;
		s->arg_start = NULL;
	}

	s->state = (s->command != OC_SMTP_AUTH) ? sw_start : sw_argument;

	return NGX_OK;

invalid:

	s->state = sw_start;
	s->arg_start = NULL;

	return OC_SMTP_PARSE_INVALID_COMMAND;
}


ngx_int_t
oc_smtp_read_command(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ssize_t                    n;
	ngx_int_t                  rc;
	ngx_str_t                  l;
	oc_smtp_core_srv_conf_t  *cscf;

	n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

	if (n == NGX_ERROR || n == 0) {
		oc_smtp_close_connection(c);
		return NGX_ERROR;
	}

	if (n > 0) {
		s->buffer->last += n;
	}

	if (n == NGX_AGAIN) {
		if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
			oc_smtp_session_internal_server_error(s);
			return NGX_ERROR;
		}

		return NGX_AGAIN;
	}

	cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

	rc = oc_smtp_parse_command(s);

	if (rc == NGX_AGAIN) {

		if (s->buffer->last < s->buffer->end) {
			return rc;
		}

		l.len = s->buffer->last - s->buffer->start;
		l.data = s->buffer->start;

		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent too long command \"%V\"", &l);

		s->quit = 1;

		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	if (rc == OC_SMTP_PARSE_INVALID_COMMAND) {
		return rc;
	}

	if (rc == NGX_ERROR) {
		oc_smtp_close_connection(c);
		return NGX_ERROR;
	}

	return NGX_OK;
}


ngx_int_t
oc_smtp_salt(oc_smtp_session_t *s, ngx_connection_t *c,
			oc_smtp_core_srv_conf_t *cscf)
{
	s->salt.data = ngx_pnalloc(c->pool,
				sizeof(" <18446744073709551616.@>" CRLF) - 1
				+ NGX_TIME_T_LEN
				+ cscf->server_name.len);
	if (s->salt.data == NULL) {
		return NGX_ERROR;
	}

	//根据CRAM-MD5的协议规定，生成随机的验证串
	s->salt.len = ngx_sprintf(s->salt.data, "<%ul.%T@%V>" CRLF,
				ngx_random(), ngx_time(), &cscf->server_name)
		- s->salt.data;

	return NGX_OK;
}

void
oc_smtp_auth(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "oc_smtp_auth");
	s->args.nelts = 0;
	s->buffer->pos = s->buffer->start;
	s->buffer->last = s->buffer->start;
	s->state = 0;

	s->login_attempt++;

	s->authorised = 1;

	s->mail_state = oc_smtp_start;

}

ngx_int_t
oc_smtp_cmd_auth_login_username(oc_smtp_session_t *s, ngx_connection_t *c,
			ngx_uint_t n)
{
	ngx_str_t  *arg;

	arg = s->args.elts;

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth login username: \"%V\"", &arg[n]);

	s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
	if (s->login.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&s->login, &arg[n]) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid base64 encoding in AUTH LOGIN command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth login username: \"%V\"", &s->login);

	return NGX_OK;

}

ngx_int_t
oc_smtp_cmd_auth_login_password(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ngx_str_t  *arg;

	arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth login password: \"%V\"", &arg[0]);
#endif

	s->passwd.data = ngx_pnalloc(c->pool,
				ngx_base64_decoded_length(arg[0].len));
	if (s->passwd.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&s->passwd, &arg[0]) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid base64 encoding in AUTH LOGIN command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

#if (NGX_DEBUG_MAIL_PASSWD)
	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth login password: \"%V\"", &s->passwd);
#endif

	return NGX_DONE;

}

ngx_int_t
oc_smtp_cmd_auth_cram_md5_salt(oc_smtp_session_t *s, ngx_connection_t *c,
			char *prefix, size_t len)
{
	u_char      *p;
	ngx_str_t    salt;
	ngx_uint_t   n;

	p = ngx_pnalloc(c->pool, len + ngx_base64_encoded_length(s->salt.len) + 2);
	if (p == NULL) {
		return NGX_ERROR;
	}

	salt.data = ngx_cpymem(p, prefix, len);
	s->salt.len -= 2;

	ngx_encode_base64(&salt, &s->salt);

	s->salt.len += 2;
	n = len + salt.len;
	p[n++] = CR; p[n++] = LF;

	s->out.len = n;
	s->out.data = p;

	return NGX_OK;

}

ngx_int_t
oc_smtp_cmd_auth_cram_md5(oc_smtp_session_t *s, ngx_connection_t *c)
{
	u_char	   *p, *last;
	ngx_str_t  *arg;

	arg = s->args.elts;

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth cram-md5: \"%V\"", &arg[0]);

	s->login.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[0].len));
	if (s->login.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&s->login, &arg[0]) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid base64 encoding in AUTH CRAM-MD5 command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	p = s->login.data;
	last = p + s->login.len;

	while (p < last) {
		if (*p++ == ' ') {
			s->login.len = p - s->login.data - 1;
			s->passwd.len = last - p;
			s->passwd.data = p;
			break;
		}
	}

	if (s->passwd.len != 32) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid CRAM-MD5 hash in AUTH CRAM-MD5 command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth cram-md5: \"%V\" \"%V\"", &s->login, &s->passwd);

	s->auth_method = OC_SMTP_AUTH_CRAM_MD5;

	return NGX_DONE;

}

ngx_int_t
oc_smtp_cmd_auth_plain(oc_smtp_session_t *s, ngx_connection_t *c, ngx_uint_t n)
{
	u_char	   *p, *last;
	ngx_str_t  *arg, plain;

	arg = s->args.elts;

#if (NGX_DEBUG_MAIL_PASSWD)
	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth plain: \"%V\"", &arg[n]);
#endif

	plain.data = ngx_pnalloc(c->pool, ngx_base64_decoded_length(arg[n].len));
	if (plain.data == NULL) {
		return NGX_ERROR;
	}

	if (ngx_decode_base64(&plain, &arg[n]) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid base64 encoding in AUTH PLAIN command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	p = plain.data;
	last = p + plain.len;

	while (p < last && *p++) { /* void */ }

	if (p == last) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid login in AUTH PLAIN command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	s->login.data = p;

	while (p < last && *p) { p++; }

	if (p == last) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
					"client sent invalid password in AUTH PLAIN command");
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	s->login.len = p++ - s->login.data;

	s->passwd.len = last - p;
	s->passwd.data = p;

#if (NGX_DEBUG_MAIL_PASSWD)
	ngx_log_debug2(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"mail auth plain: \"%V\" \"%V\"", &s->login, &s->passwd);
#endif

	return NGX_DONE;

}


ngx_int_t
oc_smtp_cmd_auth_parse(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ngx_str_t                 *arg;

#if (OC_SMTP_SSL)
	if (oc_smtp_starttls_only(s, c)) {
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}
#endif

	arg = s->args.elts;

	if (arg[0].len == 5) {

		if (ngx_strncasecmp(arg[0].data, (u_char *) "LOGIN", 5) == 0) {

			if (s->args.nelts == 1) {
				return OC_SMTP_AUTH_LOGIN;
			}

			if (s->args.nelts == 2) {
				return OC_SMTP_AUTH_LOGIN_USERNAME;
			}

			return OC_SMTP_PARSE_INVALID_COMMAND;
		}

		if (ngx_strncasecmp(arg[0].data, (u_char *) "PLAIN", 5) == 0) {

			if (s->args.nelts == 1) {
				return OC_SMTP_AUTH_PLAIN;
			}

			if (s->args.nelts == 2) {
				return oc_smtp_cmd_auth_plain(s, c, 1);
			}
		}

		return OC_SMTP_PARSE_INVALID_COMMAND;
	}

	if (arg[0].len == 8) {

		if (s->args.nelts != 1) {
			return OC_SMTP_PARSE_INVALID_COMMAND;
		}

		if (ngx_strncasecmp(arg[0].data, (u_char *) "CRAM-MD5", 8) == 0) {
			return OC_SMTP_AUTH_CRAM_MD5;
		}
	}

	return OC_SMTP_PARSE_INVALID_COMMAND;
}


void
oc_smtp_auth_state(ngx_event_t *rev)
{
	ngx_int_t            rc;
	ngx_connection_t    *c;
	oc_smtp_session_t  *s;
	oc_smtp_core_srv_conf_t  *cscf;


	c = rev->data;
	s = c->data;
	cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

	ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp auth state");

	if (rev->timedout) {
		ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
		c->timedout = 1;
		oc_smtp_close_connection(c);
		return;
	}

	if (s->out.len) {
		ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "smtp send handler busy");
		s->blocked = 1;
		return;
	}

	s->blocked = 0;


	rc = oc_smtp_read_command(s, c);

	if (rc == NGX_AGAIN || rc == NGX_ERROR) {
		return;
	}

	//只要有正常的数据，就重置timer，重新计时
	ngx_add_timer(rev, cscf->timeout);

	ngx_str_set(&s->out, smtp_ok);

	if (rc == NGX_OK) {
		switch (s->mail_state) {

			case oc_smtp_start:

				switch (s->command) {

					case OC_SMTP_HELO:
					case OC_SMTP_EHLO:
						rc = oc_smtp_cmd_helo(s, c);
						break;

					case OC_SMTP_AUTH:
						rc = oc_smtp_cmd_auth(s, c);
						break;

					case OC_SMTP_QUIT:
						s->quit = 1;
						ngx_str_set(&s->out, smtp_bye);
						break;

					case OC_SMTP_MAIL:
						rc = oc_smtp_cmd_mail(s, c);
						break;

					case OC_SMTP_RCPT:
						rc = oc_smtp_cmd_rcpt(s, c);
						break;

					case OC_SMTP_RSET:
						rc = oc_smtp_cmd_rset(s, c);
						break;

					case OC_SMTP_NOOP:
						break;

					case OC_SMTP_STARTTLS:
						rc = oc_smtp_cmd_starttls(s, c);
						ngx_str_set(&s->out, smtp_starttls);
						break;

					default:
						rc = OC_SMTP_PARSE_INVALID_COMMAND;
						break;
				}

				break;

			case oc_smtp_auth_login_username:
				rc = oc_smtp_cmd_auth_login_username(s, c, 0);

				ngx_str_set(&s->out, smtp_password);
				s->mail_state = oc_smtp_auth_login_password;
				break;

			case oc_smtp_auth_login_password:
				rc = oc_smtp_cmd_auth_login_password(s, c);
				break;

			case oc_smtp_auth_plain:
				rc = oc_smtp_cmd_auth_plain(s, c, 0);
				break;

			case oc_smtp_auth_cram_md5:
				rc = oc_smtp_cmd_auth_cram_md5(s, c);
				break;
		}
	}

	switch (rc) {

		case NGX_DONE:
			oc_smtp_auth(s, c);
			//todo: 这里应该在oc_smtp_auth()中处理
			oc_smtp_send(c->write);
			return;

		case NGX_ERROR:
			oc_smtp_session_internal_server_error(s);
			return;

		case OC_SMTP_PARSE_INVALID_COMMAND:
			s->mail_state = oc_smtp_start;
			s->state = 0;
			ngx_str_set(&s->out, smtp_invalid_command);

			/* fall through */

		case NGX_OK:
			s->args.nelts = 0;
			s->buffer->pos = s->buffer->start;
			s->buffer->last = s->buffer->start;

			if (s->state) {
				s->arg_start = s->buffer->start;
			}

			oc_smtp_send(c->write);
	}
}

static ngx_int_t
oc_smtp_cmd_helo(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ngx_str_t                 *arg;
	oc_smtp_core_srv_conf_t  *cscf;

	if (s->args.nelts != 1) {
		ngx_str_set(&s->out, smtp_invalid_argument);
		s->state = 0;
		return NGX_OK;
	}

	arg = s->args.elts;

	s->smtp_helo.len = arg[0].len;

	s->smtp_helo.data = ngx_pnalloc(c->pool, arg[0].len);
	if (s->smtp_helo.data == NULL) {
		return NGX_ERROR;
	}

	ngx_memcpy(s->smtp_helo.data, arg[0].data, arg[0].len);

	//清空from
	ngx_str_null(&s->smtp_from);
	//清空收件件列表rcpts
	s->smtp_rcpts.nelts = 0;

	cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

	if (s->command == OC_SMTP_HELO) {
		s->out = cscf->helo_server_name;

	} else {
		s->esmtp = 1;

#if (OC_SMTP_SSL)

		if (c->ssl == NULL) {
			oc_smtp_ssl_conf_t  *sslcf;

			sslcf = oc_smtp_get_module_srv_conf(s, oc_smtp_ssl_module);

			if (sslcf->starttls == OC_SMTP_STARTTLS_ON) {
				s->out = sscf->starttls_capability;
				return NGX_OK;
			}

			if (sslcf->starttls == OC_SMTP_STARTTLS_ONLY) {
				s->out = sscf->starttls_only_capability;
				return NGX_OK;
			}
		}
#endif

		s->out = cscf->capability;
	}

	return NGX_OK;
}

static ngx_int_t 
oc_smtp_cmd_auth(oc_smtp_session_t *s, ngx_connection_t *c)
{
	ngx_int_t				   rc;
	oc_smtp_core_srv_conf_t  *cscf;

#if (OC_SMTP_SSL)
	if (oc_smtp_starttls_only(s, c)) {
		return OC_SMTP_PARSE_INVALID_COMMAND;
	}
#endif

	if (s->args.nelts == 0) {
		ngx_str_set(&s->out, smtp_invalid_argument);
		s->state = 0;
		return NGX_OK;
	}

	rc = oc_smtp_cmd_auth_parse(s, c);

	switch (rc) {

		case OC_SMTP_AUTH_LOGIN:

			ngx_str_set(&s->out, smtp_username);
			s->mail_state = oc_smtp_auth_login_username;

			return NGX_OK;

		case OC_SMTP_AUTH_LOGIN_USERNAME:

			ngx_str_set(&s->out, smtp_password);
			s->mail_state = oc_smtp_auth_login_password;

			return oc_smtp_cmd_auth_login_username(s, c, 1);

		case OC_SMTP_AUTH_PLAIN:

			ngx_str_set(&s->out, smtp_next);
			s->mail_state = oc_smtp_auth_plain;

			return NGX_OK;

		case OC_SMTP_AUTH_CRAM_MD5:

			cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

			if (!(cscf->auth_methods & OC_SMTP_AUTH_CRAM_MD5_ENABLED)) {
				return OC_SMTP_PARSE_INVALID_COMMAND;
			}

			if (s->salt.data == NULL) {

				if (oc_smtp_salt(s, c, cscf) != NGX_OK) {
					return NGX_ERROR;
				}
			}

			if (oc_smtp_cmd_auth_cram_md5_salt(s, c, "334 ", 4) == NGX_OK) {
				s->mail_state = oc_smtp_auth_cram_md5;
				return NGX_OK;
			}

			return NGX_ERROR;
	}

	return rc;

}

static ngx_int_t oc_smtp_cmd_mail(oc_smtp_session_t *s, ngx_connection_t *c)
{
	u_char					   ch;
	ngx_str_t					l;
	ngx_uint_t 				i;
	oc_smtp_core_srv_conf_t  *cscf;
	ngx_str_t	*args;

	cscf = oc_smtp_get_module_srv_conf(s, oc_smtp_core_module);

	if (cscf->auth_required && !(s->authorised)) {
		oc_smtp_smtp_log_rejected_command(s, c, "client was rejected: \"%V\"");
		ngx_str_set(&s->out, smtp_auth_required);
		return NGX_OK;
	}


	/* auth none */

	if (s->smtp_from.len) {
		ngx_str_set(&s->out, smtp_bad_sequence);
		return NGX_OK;
	}

	
	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"smtp MAIL command argument count :\"%d\"", s->args.nelts);	

	if (s->args.nelts < 1) {
		ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"smtp mail from : not enough arguments\"%d\"");	
		ngx_str_set(&s->out, smtp_invalid_argument);
		return NGX_OK;
	}

	//处理from参数
	args = s->args.elts;
	

	l.len = s->buffer->last - s->buffer->start;
	l.data = s->buffer->start;

	for (i = 0; i < l.len; i++) {
		ch = l.data[i];

		if (ch != CR && ch != LF) {
			continue;
		}

		l.data[i] = ' ';
	}

	while (i) {
		if (l.data[i - 1] != ' ') {
			break;
		}

		i--;
	}

	l.len = i;

	s->smtp_from.len = l.len;

	s->smtp_from.data = ngx_pnalloc(c->pool, l.len);
	if (s->smtp_from.data == NULL) {
		return NGX_ERROR;
	}

	ngx_memcpy(s->smtp_from.data, l.data, l.len);

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				"smtp mail from:\"%V\"", &s->smtp_from);

	ngx_str_set(&s->out, smtp_ok);

	return NGX_OK;

}

static ngx_int_t oc_smtp_cmd_starttls(oc_smtp_session_t *s,
			ngx_connection_t *c)
{
	return NGX_OK;
}

static ngx_int_t 
oc_smtp_cmd_rset(oc_smtp_session_t *s, ngx_connection_t *c)
{
	return NGX_OK;
}

static ngx_int_t 
oc_smtp_cmd_rcpt(oc_smtp_session_t *s, ngx_connection_t *c)
{
	u_char		ch;
	ngx_str_t	l, *rcpt;
	ngx_uint_t	i;

	if (s->smtp_from.len == 0) {
		ngx_str_set(&s->out, smtp_bad_sequence);
		return NGX_OK;
	}

	l.len = s->buffer->last - s->buffer->start;
	l.data = s->buffer->start;

	for (i = 0; i < l.len; i++) {
		ch = l.data[i];

		if (ch != CR && ch != LF) {
			continue;
		}

		l.data[i] = ' ';
	}

	while (i) {
		if (l.data[i - 1] != ' ') {
			break;
		}

		i--;
	}

	l.len = i;

	rcpt = ngx_array_push(&s->smtp_rcpts);
	rcpt->len = l.len;
	rcpt->data = ngx_pnalloc(c->pool, l.len);

	if (rcpt->data == NULL) {
		return NGX_ERROR;
	}

	ngx_memcpy(rcpt->data, l.data, l.len);

	ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,
				   "smtp rcpt to:\"%V\"", rcpt);

	//s->auth_method = NGX_MAIL_AUTH_NONE;

	//return NGX_DONE;


	return NGX_OK;
}

static void
oc_smtp_smtp_log_rejected_command(oc_smtp_session_t *s, ngx_connection_t *c,
			char *err)
{
	u_char      ch;
	ngx_str_t   cmd;
	ngx_uint_t  i;

	if (c->log->log_level < NGX_LOG_INFO) {
		return;
	}

	cmd.len = s->buffer->last - s->buffer->start;
	cmd.data = s->buffer->start;

	for (i = 0; i < cmd.len; i++) {
		ch = cmd.data[i];

		if (ch != CR && ch != LF) {
			continue;
		}

		cmd.data[i] = '_';
	}

	cmd.len = i;

	ngx_log_error(NGX_LOG_INFO, c->log, 0, err, &cmd);
}

