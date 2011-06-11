#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>


static char *oc_smtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t oc_smtp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
			oc_smtp_listen_t *listen);

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

	//Ϊctx����ռ�
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



	//������ɣ��ָ�cf������
	*cf = pcf;

	ngx_log_stderr(0, "ngx_conf_parse finished");
	

	//Add port
	if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(oc_smtp_conf_port_t))
				!= NGX_OK)
	{
		return NGX_CONF_ERROR;
	}

	for (i = 0; i < cmcf->listen.nelts; i++) {
		if (oc_smtp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
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

	sa = (struct sockaddr *) &listen->sockaddr;

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

