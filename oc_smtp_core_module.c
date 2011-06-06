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


