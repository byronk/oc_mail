#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_mail.h>


static char *oc_smtp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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
	ngx_uint_t                  m,mi;
	oc_smtp_conf_ctx_t			*ctx;
	oc_smtp_module_t            *module;

	ngx_log_stderr(0, "SMTP conf block");

	//Îªctx·ÖÅä¿Õ¼ä
	ctx = ngx_pcalloc(cf->pool, sizeof(oc_smtp_conf_ctx_t));
	if (ctx == NULL) {
		return NGX_CONF_ERROR;
	}

	*(oc_smtp_conf_ctx_t **)conf = ctx;

	//count the number of the http modules and set up their indices
	oc_smtp_max_module = 0;
	for (m = 0; ngx_modules[m]; m++) {
		if (ngx_modules[m]->type != OC_SMTP_MODULE) {
			continue;
		}

		ngx_modules[m]->ctx_index = oc_smtp_max_module++;
	}

	/* the mail main_conf context, it is the same in the all mail contexts */

	ctx->main_conf = ngx_pcalloc(cf->pool,
				sizeof(void *) * oc_smtp_max_module);
	if (ctx->main_conf == NULL) {
		return NGX_CONF_ERROR;
	}

	/*
	 *  the mail null srv_conf context, it is used to merge
	 *  the server{}s' srv_conf's
	 */

	ctx->srv_conf = ngx_pcalloc(cf->pool, 
				sizeof(void *) * oc_smtp_max_module);
	if (ctx->srv_conf == NULL) {
		return NGX_CONF_ERROR;
	}

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







	rv = ngx_conf_parse(cf, NULL);

	if (rv != NGX_CONF_OK) {
		return rv;
	}

	return NGX_CONF_OK;
}
