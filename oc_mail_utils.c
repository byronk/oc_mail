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
	�ʼ���ַ�ĸ�ʽ:  local-part@domain

	local-part����ĸ�����ֺ������ַ���ɣ��ܳ��Ȳ�����64
	domain����ĸ��"."��ɣ�������253
	�ʼ���ַ�ܳ��Ȳ�����254
	*/
	ngx_uint_t                  i;
	ngx_uint_t                  last_dot = 0;

	u_char char_spec[]= "!#$%&'*+-/=?^_`{|}~";
	u_char ca[] = {0,0};  //����һ����������strnstr()����

	if (addr->len > OC_MAIL_ADDR_LEN_MAX) 
		return OC_MAIL_ADDR_TOO_LONG;

	//��λ"@"�ַ���ͬʱ���local part���ַ��Ƿ���ϱ�׼
	for (i=0; i<addr->len; i++){
		ca[0] = addr->data[i];

		if (ca[0] == '@'){
			if (i > OC_MAIL_ADDR_LOCAL_PART_LEN_MAX)
				return OC_MAIL_ADDR_LOCAL_TOO_LONG;
			
			break;
		}

		if (ca[0] == '.') {
			if (last_dot) {
				//��������"."�ǲ������
				return OC_MAIL_ADDR_INVALID;
			}

			last_dot = 1;

			continue;
		} else {
			last_dot = 0;
		}

		//��Ч�ַ��ж�
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
		//local part�Ŀ�ʼ�ͽ�����������'.'
		return OC_MAIL_ADDR_INVALID;
	}

	if (i==1){
		//local part ��������Ϊ0
		return OC_MAIL_ADDR_INVALID;
	}

	if (addr->len - i - 1 == 0) {
		//�������Ȳ�����Ϊ��
		return OC_MAIL_ADDR_INVALID;
	}

	//todo: ����������Ч�Խ����ж�
	


	return OC_MAIL_ADDR_OK;
}





