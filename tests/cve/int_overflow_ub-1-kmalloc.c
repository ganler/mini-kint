// http://www.securityfocus.com/archive/1/362953

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

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
