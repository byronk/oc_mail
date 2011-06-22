#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>

static void *oc_smtp_core_create_main_conf(ngx_conf_t *cf);
static void *oc_smtp_core_create_srv_conf(ngx_conf_t *cf);
static char *oc_smtp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
			void *child);
static char *oc_smtp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
			void *conf);
static char *oc_smtp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
			void *conf);


static ngx_conf_bitmask_t  oc_smtp_auth_methods[] = {
    { ngx_string("plain"), OC_SMTP_AUTH_PLAIN_ENABLED },
    { ngx_string("login"), OC_SMTP_AUTH_LOGIN_ENABLED },
    { ngx_string("cram-md5"), OC_SMTP_AUTH_CRAM_MD5_ENABLED },
    { ngx_string("none"), OC_SMTP_AUTH_NONE_ENABLED },
    { ngx_null_string, 0 }
};

static ngx_str_t  oc_smtp_auth_methods_names[] = {
    ngx_string("PLAIN"),
    ngx_string("LOGIN"),
    ngx_null_string,  /* APOP */
    ngx_string("CRAM-MD5"),
    ngx_null_string   /* NONE */
};



static ngx_command_t  oc_smtp_core_commands[] = {

	{ ngx_string("server"),
		OC_SMTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
		oc_smtp_core_server,
		0,
		0,
		NULL },

	{ ngx_string("listen"),
		OC_SMTP_SRV_CONF|NGX_CONF_TAKE12,
		oc_smtp_core_listen,
		OC_SMTP_SRV_CONF_OFFSET,
		0,
		NULL },

	{ ngx_string("so_keepalive"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, so_keepalive),
		NULL },

	{ ngx_string("timeout"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_msec_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, timeout),
		NULL },

	{ ngx_string("server_name"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, server_name),
		NULL },

	{ ngx_string("smtp_client_buffer"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, client_buffer_size),
		NULL },

	{ ngx_string("auth_required"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_num_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, auth_required),
		NULL },

	{ ngx_string("smtp_auth"),
		OC_SMTP_MAIN_CONF|OC_SMTP_SRV_CONF|NGX_CONF_1MORE,
		ngx_conf_set_bitmask_slot,
		OC_SMTP_SRV_CONF_OFFSET,
		offsetof(oc_smtp_core_srv_conf_t, auth_methods),
		&oc_smtp_auth_methods },

	ngx_null_command
};

static oc_smtp_module_t  oc_smtp_core_module_ctx = {
	oc_smtp_core_create_main_conf,        /* create main configuration */
	NULL,                                  /* init main configuration */

	oc_smtp_core_create_srv_conf,         /* create server configuration */
	oc_smtp_core_merge_srv_conf           /* merge server configuration */
};

ngx_module_t  oc_smtp_core_module = {
	NGX_MODULE_V1,
	&oc_smtp_core_module_ctx,             /* module context */
	oc_smtp_core_commands,                /* module directives */
	OC_SMTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};


static void *
oc_smtp_core_create_main_conf(ngx_conf_t *cf)
{
	oc_smtp_core_main_conf_t  *cmcf;

	cmcf = ngx_pcalloc(cf->pool, sizeof(oc_smtp_core_main_conf_t));
	if (cmcf == NULL) {
		return NULL;
	}

	if (ngx_array_init(&cmcf->servers, cf->pool, 4,
					sizeof(oc_smtp_core_srv_conf_t *))
				!= NGX_OK)
	{
		return NULL;
	}

	if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(oc_smtp_listen_t))
				!= NGX_OK)
	{
		return NULL;
	}

	return cmcf;
}


static void *
oc_smtp_core_create_srv_conf(ngx_conf_t *cf)
{
	oc_smtp_core_srv_conf_t  *cscf;

	cscf = ngx_pcalloc(cf->pool, sizeof(oc_smtp_core_srv_conf_t));
	if (cscf == NULL) {
		return NULL;
	}

	cscf->timeout = NGX_CONF_UNSET_MSEC;
	cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
	cscf->so_keepalive = NGX_CONF_UNSET;
	cscf->client_buffer_size = NGX_CONF_UNSET_SIZE;
	cscf->auth_required = NGX_CONF_UNSET_UINT;

	if (ngx_array_init(&cscf->capabilities, cf->pool, 4, sizeof(ngx_str_t))
        != NGX_OK)
    {
        return NULL;
    }


	return cscf;
}


static char *
oc_smtp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	oc_smtp_core_srv_conf_t *prev = parent;
	oc_smtp_core_srv_conf_t *conf = child;

	size_t                     size;
	ngx_str_t                 *c;
	u_char                    *p, *auth, *last;
	ngx_uint_t                 i, m, auth_enabled;

	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
	ngx_log_stderr(0, "time out: %d", conf->timeout);
	ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
				30000);

	ngx_conf_merge_size_value(conf->client_buffer_size,
				prev->client_buffer_size,
				(size_t) ngx_pagesize);

	ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);

	//暂时默认定为不需要验证
	ngx_conf_merge_uint_value(conf->auth_required, prev->auth_required, 0);

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                          prev->auth_methods,
                          (NGX_CONF_BITMASK_SET
                           |OC_SMTP_AUTH_PLAIN_ENABLED
                           |OC_SMTP_AUTH_LOGIN_ENABLED));

	ngx_log_stderr(0, "auth_methods: %d", conf->auth_methods);

	ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

	if (conf->server_name.len == 0) {
		conf->server_name = cf->cycle->hostname;
	}

	//生成greeting
	size = sizeof("220  ESMTP ready" CRLF) - 1 + conf->server_name.len;

	p = ngx_pnalloc(cf->pool, size);
	if (p == NULL) {
		return NGX_CONF_ERROR;
	}

	conf->greeting.len = size;
	conf->greeting.data = p;

	*p++ = '2'; *p++ = '2'; *p++ = '0'; *p++ = ' ';
	p = ngx_cpymem(p, conf->server_name.data, conf->server_name.len);
	ngx_memcpy(p, " ESMTP ready" CRLF, sizeof(" ESMTP ready" CRLF) - 1);

	//生成HELO的响应字符串
    size = sizeof("250 " CRLF) - 1 + conf->server_name.len;

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->helo_server_name.len = size;
    conf->helo_server_name.data = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
    p = ngx_cpymem(p, conf->server_name.data, conf->server_name.len);
    *p++ = CR; *p = LF;

	//生成auth capabilities，用于EHLO
	if (conf->capabilities.nelts == 0) {
        conf->capabilities = prev->capabilities;
    }

    size = sizeof("250-") - 1 + conf->server_name.len + sizeof(CRLF) - 1;

    c = conf->capabilities.elts;
    for (i = 0; i < conf->capabilities.nelts; i++) {
        size += sizeof("250 ") - 1 + c[i].len + sizeof(CRLF) - 1;
    }

    auth_enabled = 0;

    for (m = OC_SMTP_AUTH_PLAIN_ENABLED, i = 0;
         m <= OC_SMTP_AUTH_CRAM_MD5_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += 1 + oc_smtp_auth_methods_names[i].len;
            auth_enabled = 1;
        }
    }

    if (auth_enabled) {
        size += sizeof("250 AUTH") - 1 + sizeof(CRLF) - 1;
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->capability.len = size;
    conf->capability.data = p;

    last = p;

    *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
    p = ngx_cpymem(p, conf->server_name.data, conf->server_name.len);
    *p++ = CR; *p++ = LF;

    for (i = 0; i < conf->capabilities.nelts; i++) {
        last = p;
        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = '-';
        p = ngx_cpymem(p, c[i].data, c[i].len);
        *p++ = CR; *p++ = LF;
    }

    auth = p;

    if (auth_enabled) {
        last = p;

        *p++ = '2'; *p++ = '5'; *p++ = '0'; *p++ = ' ';
        *p++ = 'A'; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';

        for (m = OC_SMTP_AUTH_PLAIN_ENABLED, i = 0;
             m <= OC_SMTP_AUTH_CRAM_MD5_ENABLED;
             m <<= 1, i++)
        {
            if (m & conf->auth_methods) {
                *p++ = ' ';
                p = ngx_cpymem(p, oc_smtp_auth_methods_names[i].data,
                               oc_smtp_auth_methods_names[i].len);
            }
        }

        *p++ = CR; *p = LF;

    } else {
        last[3] = ' ';
    }

	return NGX_CONF_OK;
}


static char *
oc_smtp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char                       *rv;
	void                       *mconf;
	ngx_uint_t                  m;
	ngx_conf_t                  pcf;
	oc_smtp_module_t          *module;
	oc_smtp_conf_ctx_t        *ctx, *mail_ctx;
	oc_smtp_core_srv_conf_t   *cscf, **cscfp;
	oc_smtp_core_main_conf_t  *cmcf;

	ctx = ngx_pcalloc(cf->pool, sizeof(oc_smtp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	mail_ctx = cf->ctx;
	ctx->main_conf = mail_ctx->main_conf;

	/* the server{}'s srv_conf */

	ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * oc_smtp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != OC_SMTP_MODULE) {
			continue;
		}

		module = ngx_modules[m]->ctx;

		if (module->create_srv_conf) {
			mconf = module->create_srv_conf(cf);
			if (mconf == NULL) {
				return NGX_CONF_ERROR;
			}

			ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
		}
	}

	/* the server configuration context */

	cscf = ctx->srv_conf[oc_smtp_core_module.ctx_index];
	cscf->ctx = ctx;

	cmcf = ctx->main_conf[oc_smtp_core_module.ctx_index];

	cscfp = ngx_array_push(&cmcf->servers);
	if (cscfp == NULL) {
		return NGX_CONF_ERROR;
	}

	*cscfp = cscf;


	/* parse inside server{} */

	pcf = *cf;
	cf->ctx = ctx;
	cf->cmd_type = OC_SMTP_SRV_CONF;

	rv = ngx_conf_parse(cf, NULL);

	*cf = pcf;

	return rv;
}

static char *
oc_smtp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	//oc_smtp_core_srv_conf_t  *cscf = conf;

	size_t                      len, off;
	in_port_t                   port;
	ngx_str_t                  *value;
	ngx_url_t                   u;
	ngx_uint_t                  i;
	struct sockaddr            *sa;
	oc_smtp_listen_t          *ls;
	struct sockaddr_in         *sin;
	oc_smtp_core_main_conf_t  *cmcf;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6        *sin6;
#endif

	value = cf->args->elts;

	ngx_memzero(&u, sizeof(ngx_url_t));

	u.url = value[1];
	u.listen = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
		if (u.err) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"%s in \"%V\" of the \"listen\" directive",
						u.err, &u.url);
		}

		return NGX_CONF_ERROR;
	}

	ngx_log_stderr(0, "parse listen: url: %s", u.url.data);
	ngx_log_stderr(0, "parse listen: socklen: %d", u.socklen);
	ngx_log_stderr(0, "parse listen: family: %d", u.family);

	sin = (struct sockaddr_in *)&u.sockaddr;
	ngx_log_stderr(0, "parse listen: sin port: %d", ntohs(sin->sin_port));	

	cmcf = oc_smtp_conf_get_module_main_conf(cf, oc_smtp_core_module);

	ls = cmcf->listen.elts;

	/* 判断有没有重复监听端口 */
	for (i = 0; i < cmcf->listen.nelts; i++) {

		sa = (struct sockaddr *) ls[i].sockaddr;
		if (sa->sa_family != u.family) {
			continue;
		}
		switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
			case AF_INET6:
				off = offsetof(struct sockaddr_in6, sin6_addr);
				len = 16;
				sin6 = (struct sockaddr_in6 *) sa;
				port = sin6->sin6_port;
				break;
#endif

			default: /* AF_INET */
				off = offsetof(struct sockaddr_in, sin_addr);
				len = 4;
				sin = (struct sockaddr_in *) sa;
				port = sin->sin_port;
				break;
		}

		if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
			continue;
		}

		if (port != u.port) {
			continue;
		}

		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"duplicate \"%V\" address and port pair", &u.url);
		return NGX_CONF_ERROR;
	}

	/* 新建一个listen_t并添加到array中 */
	ls = ngx_array_push(&cmcf->listen);
	if (ls == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_memzero(ls, sizeof(oc_smtp_listen_t));

	/* 以下代码都是对新成员的赋值  */
	ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

	ls->socklen = u.socklen;
	ls->wildcard = u.wildcard;
	ls->ctx = cf->ctx;

	for (i = 2; i < cf->args->nelts; i++) {
		if (ngx_strcmp(value[i].data, "bind") == 0) {
			ls->bind = 1;
			continue;
		}

		if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
			struct sockaddr  *sa;
			u_char            buf[NGX_SOCKADDR_STRLEN];

			sa = (struct sockaddr *) ls->sockaddr;

			if (sa->sa_family == AF_INET6) {

				if (ngx_strcmp(&value[i].data[10], "n") == 0) {
					ls->ipv6only = 1;

				} else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
					ls->ipv6only = 2;

				} else {
					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
								"invalid ipv6only flags \"%s\"",
								&value[i].data[9]);
					return NGX_CONF_ERROR;
				}

				ls->bind = 1;

			} else {
				len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);

				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"ipv6only is not supported "
							"on addr \"%*s\", ignored", len, buf);
			}

			continue;
#else
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"bind ipv6only is not supported "
						"on this platform");
			return NGX_CONF_ERROR;
#endif
		}

		if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (OC_SMTP_SSL)
			ls->ssl = 1;
			continue;
#else
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"the \"ssl\" parameter requires "
						"oc_smtp_ssl_module");
			return NGX_CONF_ERROR;
#endif
		}

		/* 解析到这里就是不支持的参数了 */
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"the invalid \"%V\" parameter", &value[i]);
		return NGX_CONF_ERROR;
	}

	//输出ls的内容
	ngx_log_stderr(0, "ls: socklen: %d", ls->socklen);
	ngx_log_stderr(0, "ls: bind: %d", ls->bind);
	ngx_log_stderr(0, "ls: wildcard: %d", ls->wildcard);





	return NGX_CONF_OK;
}
