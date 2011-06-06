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


	return cscf;
}


static char *
oc_smtp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	oc_smtp_core_srv_conf_t *prev = parent;
	oc_smtp_core_srv_conf_t *conf = child;

	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
	ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
				30000);

	ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);


	ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

	if (conf->server_name.len == 0) {
		conf->server_name = cf->cycle->hostname;
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
	ngx_str_t                  *value;
	ngx_url_t                   u;

	ngx_log_stderr(0, "Parse SMTP server conf: listen");



	value = cf->args->elts;
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

	ngx_log_stderr(0, "server listen: %s", u.url.data);




	return NGX_CONF_OK;
}


