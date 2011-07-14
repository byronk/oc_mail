#ifndef _OC_MAIL_UTILS_H_INCLUDED_
#define _OC_MAIL_UTILS_H_INCLUDED_

#define OC_MAIL_ADDR_OK				0
#define OC_MAIL_ADDR_TOO_LONG		-1
#define OC_MAIL_ADDR_LOCAL_TOO_LONG -2
#define OC_MAIL_ADDR_INVALID		-3

#define OC_MAIL_ADDR_LOCAL_PART_LEN_MAX	64
#define OC_MAIL_ADDR_DOMAIN_LEN_MAX	253
#define OC_MAIL_ADDR_LEN_MAX	254


ngx_int_t oc_mail_addr_validate(ngx_str_t *addr);


#endif

