#include <ngx_config.h>
#include <ngx_core.h>

#define OC_MAIL_ADDR_OK				0
#define OC_MAIL_ADDR_TOO_LONG		-1
#define OC_MAIL_ADDR_LOCAL_TOO_LONG -2
#define OC_MAIL_ADDR_INVALID		-3

#define OC_MAIL_ADDR_LOCAL_PART_LEN_MAX	64
#define OC_MAIL_ADDR_DOMAIN_LEN_MAX	253
#define OC_MAIL_ADDR_LEN_MAX	254



/* check the mail address validity */
ngx_int_t 
oc_mail_addr_validate(ngx_str_t *addr)
{
	/*
	邮件地址的格式:  local-part@domain

	local-part由字母、数字和特殊字符组成，总长度不超过64
	domain由字母和"."组成，不超过253
	邮件地址总长度不超过254
	*/
	ngx_uint_t                  i;
	ngx_uint_t                  last_dot = 0;

	u_char char_spec[]= "!#$%&'*+-/=?^_`{|}~";
	u_char ca[] = {0,0};  //声明一个数组用于strnstr()函数

	if (addr->len > OC_MAIL_ADDR_LEN_MAX) 
		return OC_MAIL_ADDR_TOO_LONG;

	//定位"@"字符，同时检查local part的字符是否符合标准
	for (i=0; i<addr->len; i++){
		ca[0] = addr->data[i];

		if (ca[0] == '@'){
			if (i > OC_MAIL_ADDR_LOCAL_PART_LEN_MAX)
				return OC_MAIL_ADDR_LOCAL_TOO_LONG;
			
			break;
		}

		if (ca[0] == '.') {
			if (last_dot) {
				//连接两个"."是不允许的
				return OC_MAIL_ADDR_INVALID;
			}

			last_dot = 1;

			continue;
		} else {
			last_dot = 0;
		}

		//有效字符判断
		if ((ca[0]>='A' && ca[0]<='Z') ||
			(ca[0]>='a' && ca[0]<='z') ||
			(ca[0]>='0' && ca[0]<='9') ||
			ngx_strnstr(char_spec, (char *)ca, sizeof("!#$%&'*+-//=?^_`{|}~")))
		{
			continue;
		} else {
			return OC_MAIL_ADDR_INVALID;
		}
	}

	if (addr->data[0] == '.' || last_dot) {
		//local part的开始和结束是允许是'.'
		return OC_MAIL_ADDR_INVALID;
	}

	if (i==1){
		//local part 不允许长度为0
		return OC_MAIL_ADDR_INVALID;
	}

	if (addr->len - i - 1 == 0) {
		//域名长度不允许为空
		return OC_MAIL_ADDR_INVALID;
	}

	//todo: 对域名的有效性进行判断
	


	return OC_MAIL_ADDR_OK;
}





