#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>


static char *oc_smtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t oc_smtp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
			oc_smtp_listen_t *listen);

static ngx_int_t oc_smtp_add_addrs(ngx_conf_t *cf, oc_smtp_port_t *mport,
			oc_smtp_conf_addr_t *addr);

static char *oc_smtp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports);

static ngx_int_t oc_smtp_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  oc_smtp_max_module;


static ngx_command_t oc_smtp_commands[] = {
	{
		ngx_string("smtp"),
		NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
		oc_smtp_block,
		0,
		0,
		NULL 
	},
	ngx_null_command
};

static ngx_core_module_t  oc_smtp_module_ctx = {
	ngx_string("smtp"),
	NULL,
	NULL
};

ngx_module_t oc_smtp_module = {
	NGX_MODULE_V1,
	&oc_smtp_module_ctx,                  /* module context */
	oc_smtp_commands,                     /* module directives */
	NGX_CORE_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,                                  /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,                                  /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

static char *
oc_smtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char                        *rv;
	ngx_uint_t                  i, m,mi,s;
	oc_smtp_conf_ctx_t			*ctx;
	oc_smtp_module_t            *module;
	ngx_conf_t                   pcf;
	oc_smtp_core_srv_conf_t   **cscfp;
	oc_smtp_core_main_conf_t   *cmcf;
	//oc_smtp_core_srv_conf_t    *cscf;

	ngx_array_t                  ports;
	oc_smtp_listen_t           *listen;

	ngx_log_stderr(0, "SMTP conf block");

	//为ctx分配空间
	ctx = ngx_pcalloc(cf->pool, sizeof(oc_smtp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	*(oc_smtp_conf_ctx_t **)conf = ctx;

	ngx_log_stderr(0, "ctx created ok. %d", ctx);

	//count the number of the http modules and set up their indices
	oc_smtp_max_module = 0;
	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != OC_SMTP_MODULE) {
			continue;
		}

		ngx_modules[m]->ctx_index = oc_smtp_max_module++;
	}
	
	ngx_log_stderr(0, "SMTP module count: %d", oc_smtp_max_module);
	ngx_log_stderr(0, "smtp core module index: %d", oc_smtp_core_module.ctx_index);


	/* the mail main_conf context, it is the same in the all mail contexts */

	ctx->main_conf = ngx_pcalloc(cf->pool,
				sizeof(void *) * oc_smtp_max_module);
	if (ctx->main_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_log_stderr(0, "ctx->main_conf created ok");


	/*
	 *  the mail null srv_conf context, it is used to merge
	 *  the server{}s' srv_conf's
	 */

	ctx->srv_conf = ngx_pcalloc(cf->pool, 
				sizeof(void *) * oc_smtp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	ngx_log_stderr(0, "ctx->srv_conf created ok");


	/*
	 *  create the main_conf's, the null srv_conf's, and the null loc_conf's
	 *  of the all mail modules
	 */

	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != OC_SMTP_MODULE) {
			continue;
		}

		module = ngx_modules[m]->ctx;
		mi = ngx_modules[m]->ctx_index;

		if (module->create_main_conf) {
			ctx->main_conf[mi] = module->create_main_conf(cf);
			if (ctx->main_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}

		if (module->create_srv_conf) {
			ctx->srv_conf[mi] = module->create_srv_conf(cf);
			if (ctx->srv_conf[mi] == NULL) {
				return NGX_CONF_ERROR;
			}
		}
	}


	/* parse inside the smtp{} block */
	pcf = *cf;
	cf->ctx = ctx;

	cf->module_type = OC_SMTP_MODULE;
	cf->cmd_type = OC_SMTP_MAIN_CONF;

	rv = ngx_conf_parse(cf, NULL);

	if (rv != NGX_CONF_OK) {
		*cf = pcf;
		return rv;
	}

	ngx_log_stderr(0, "ngx_conf_parse smtp{}  ok");


	/* init smtp{} main_conf's, merge the server{}s' srv_conf's */
	cmcf = ctx->main_conf[oc_smtp_core_module.ctx_index];
	cscfp = cmcf->servers.elts;

	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != OC_SMTP_MODULE) {
			continue;
		}

		module = ngx_modules[m]->ctx;
		mi = ngx_modules[m]->ctx_index;


		/* init mail{} main_conf's */

		cf->ctx = ctx;

		if (module->init_main_conf) {
			rv = module->init_main_conf(cf, ctx->main_conf[mi]);
			if (rv != NGX_CONF_OK) {
				*cf = pcf;
				return rv;
			}
		}

		for (s = 0; s < cmcf->servers.nelts; s++) {

			/* merge the server{}s' srv_conf's */

			cf->ctx = cscfp[s]->ctx;

			if (module->merge_srv_conf) {
				rv = module->merge_srv_conf(cf,
							ctx->srv_conf[mi],
							cscfp[s]->ctx->srv_conf[mi]);
				if (rv != NGX_CONF_OK) {
					*cf = pcf;
					return rv;
				}
			}
		}
	}



	//解析完成，恢复cf的数据
	*cf = pcf;

	ngx_log_stderr(0, "ngx_conf_parse finished");
	

	//Add port
	if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(oc_smtp_conf_port_t))
				!= NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	listen = cmcf->listen.elts;
	ngx_log_stderr(0, "listen: %d", cmcf->listen.nelts);

	for (i = 0; i < cmcf->listen.nelts; i++) {
		if (oc_smtp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return oc_smtp_optimize_servers(cf, &ports);
}


static ngx_int_t
oc_smtp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
			oc_smtp_listen_t *listen)
{
	in_port_t              p;
	ngx_uint_t             i;
	struct sockaddr       *sa;
	struct sockaddr_in    *sin;
	oc_smtp_conf_port_t  *port;
	oc_smtp_conf_addr_t  *addr;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6   *sin6;
#endif
	ngx_log_stderr(0, "oc_smtp_add_ports");

	sa = (struct sockaddr *) &listen->sockaddr;

	ngx_log_stderr(0, "sa_family: %d", sa->sa_family);

	switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *) sa;
			p = sin6->sin6_port;
			break;
#endif

		default: /* AF_INET */
			sin = (struct sockaddr_in *) sa;
			p = sin->sin_port;
			break;
	}

	port = ports->elts;
	for (i = 0; i < ports->nelts; i++) {
		if (p == port[i].port && sa->sa_family == port[i].family) {

			/* a port is already in the port list */

			port = &port[i];
			goto found;
		}
	}

	/* add a port to the port list */

	port = ngx_array_push(ports);
	if (port == NULL) {
		return NGX_ERROR;
	}

	port->family = sa->sa_family;
	port->port = p;

	ngx_log_stderr(0, "port->family: %d", port->family);
	ngx_log_stderr(0, "port->port: %d", port->port);
	

	if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
					sizeof(oc_smtp_conf_addr_t))
				!= NGX_OK)
	{
		return NGX_ERROR;
	}

found:

	addr = ngx_array_push(&port->addrs);
	if (addr == NULL) {
		return NGX_ERROR;
	}

	addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
	addr->socklen = listen->socklen;
	ngx_log_stderr(0, "addr->socklen: %d", addr->socklen);
	addr->ctx = listen->ctx;
	addr->bind = listen->bind;
	addr->wildcard = listen->wildcard;
#if (NGX_MAIL_SSL)
	addr->ssl = listen->ssl;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
	addr->ipv6only = listen->ipv6only;
#endif

	return NGX_OK;
}

static char *
oc_smtp_optimize_servers(ngx_conf_t *cf, ngx_array_t *ports)
{
	ngx_uint_t             i, p, last, bind_wildcard;
	ngx_listening_t       *ls;
	oc_smtp_port_t       *mport;
	oc_smtp_conf_port_t  *port;
	oc_smtp_conf_addr_t  *addr;

	port = ports->elts;
	ngx_log_stderr(0, "port count: %d", ports->nelts);
	
	for (p = 0; p < ports->nelts; p++) {

		ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
					sizeof(oc_smtp_conf_addr_t), oc_smtp_cmp_conf_addrs);

		addr = port[p].addrs.elts;
		last = port[p].addrs.nelts;
		ngx_log_stderr(0, "last: %d", last);

		/*
		   * if there is the binding to the "*:port" then we need to bind()
		   * to the "*:port" only and ignore the other bindings
		   */

		if (addr[last - 1].wildcard) {
			addr[last - 1].bind = 1;
			bind_wildcard = 1;
		} else {
			bind_wildcard = 0;
		}

		i = 0;

		while (i < last) {

			if (bind_wildcard && !addr[i].bind) {
				i++;
				continue;
			}

			//创建ngx_listening_t结构，用于监听端口
			ngx_log_stderr(0, "socklen: %d", addr[i].socklen);
			
			ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
			if (ls == NULL) {
				return NGX_CONF_ERROR;
			}

			ls->addr_ntop = 1;
			ls->handler = oc_smtp_init_connection;
			ls->pool_size = 256;

			/* TODO: error_log directive */
			ls->logp = &cf->cycle->new_log;
			ls->log.data = &ls->addr_text;
			ls->log.handler = ngx_accept_log_error;
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
			ls->ipv6only = addr[i].ipv6only;
#endif

			mport = ngx_palloc(cf->pool, sizeof(oc_smtp_port_t));
			if (mport == NULL) {
				return NGX_CONF_ERROR;
			}

			ls->servers = mport;

			if (i == last - 1) {
				mport->naddrs = last;

			} else {
				mport->naddrs = 1;
				i = 0;
			}

			switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
				case AF_INET6:
					if (oc_smtp_add_addrs6(cf, mport, addr) != NGX_OK) {
						return NGX_CONF_ERROR;
					}
					break;
#endif
				default: /* AF_INET */
					if (oc_smtp_add_addrs(cf, mport, addr) != NGX_OK) {
						return NGX_CONF_ERROR;
					}
					break;
			}

			addr++;
			last--;
		}
	}

	return NGX_CONF_OK;
}

static ngx_int_t
oc_smtp_add_addrs(ngx_conf_t *cf, oc_smtp_port_t *mport,
			oc_smtp_conf_addr_t *addr)
{
	u_char              *p;
	size_t               len;
	ngx_uint_t           i;
	oc_smtp_in_addr_t  *addrs;
	struct sockaddr_in  *sin;
	u_char               buf[NGX_SOCKADDR_STRLEN];

	mport->addrs = ngx_pcalloc(cf->pool,
				mport->naddrs * sizeof(oc_smtp_in_addr_t));
	if (mport->addrs == NULL) {
		return NGX_ERROR;
	}

	addrs = mport->addrs;

	for (i = 0; i < mport->naddrs; i++) {

		sin = (struct sockaddr_in *) addr[i].sockaddr;
		addrs[i].addr = sin->sin_addr.s_addr;

		addrs[i].conf.ctx = addr[i].ctx;
#if (oc_smtp_SSL)
		addrs[i].conf.ssl = addr[i].ssl;
#endif

		len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);

		p = ngx_pnalloc(cf->pool, len);
		if (p == NULL) {
			return NGX_ERROR;
		}

		ngx_memcpy(p, buf, len);

		addrs[i].conf.addr_text.len = len;
		addrs[i].conf.addr_text.data = p;
	}

	return NGX_OK;
}

static ngx_int_t
oc_smtp_cmp_conf_addrs(const void *one, const void *two)
{
	oc_smtp_conf_addr_t  *first, *second;

	first = (oc_smtp_conf_addr_t *) one;
	second = (oc_smtp_conf_addr_t *) two;

	if (first->wildcard) {
		/* a wildcard must be the last resort, shift it to the end */
		return 1;
	}

	if (first->bind && !second->bind) {
		/* shift explicit bind()ed addresses to the start */
		return -1;
	}

	if (!first->bind && second->bind) {
		/* shift explicit bind()ed addresses to the start */
		return 1;
	}

	/* do not sort by default */

	return 0;
}

