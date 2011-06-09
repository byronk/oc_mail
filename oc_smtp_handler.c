#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <oc_smtp.h>



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

