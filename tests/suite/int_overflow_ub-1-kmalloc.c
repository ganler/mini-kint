// http://www.securityfocus.com/archive/1/362953

#include "linux.h"
#include <cstddef>

#define sctp_sk(sk)	((struct sctp_sock *)(sk))

struct sctp_endpoint {
	char *debug_name;
};

struct sctp_sock {
	struct sctp_endpoint *ep;
};

int sctp_setsockopt(struct sock *sk, char *optval, int optlen)
{
	char *tmp;

	if (NULL == (tmp = (char *)kmalloc(optlen + 1, GFP_KERNEL))) // optlen+1 may overflow
		return -ENOMEM;
	if (copy_from_user(tmp, optval, optlen)) // optlen cast from int to unsigned long
		return -EFAULT;
	tmp[optlen] = '\000';
	sctp_sk(sk)->ep->debug_name = tmp;


	return 0;
}
