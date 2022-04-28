// http://git.kernel.org/linus/83e0bbcbe2145f160fbaa109b0439dae7f4a38a9
// rose-2009-1265

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define AX25_MAX_DIGIS			8

#define AX25_BPQ_HEADER_LEN		16
#define AX25_KISS_HEADER_LEN		1

#define AX25_HEADER_LEN			17
#define AX25_ADDR_LEN			7
#define AX25_DIGI_HEADER_LEN		(AX25_MAX_DIGIS * AX25_ADDR_LEN)
#define AX25_MAX_HEADER_LEN		(AX25_HEADER_LEN + AX25_DIGI_HEADER_LEN)

#define ROSE_MIN_LEN			3

#define MSG_DONTWAIT			0x40

struct kiocb;

struct socket {
	struct sock	*sk;
};

struct msghdr {
	unsigned int	msg_flags;
};

int sys_rose_sendmsg(struct kiocb *iocb, struct socket *sock,
		 struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct sk_buff *skb;
	int err;
	int size;

#ifdef __PATCH__
	/* Build a packet */
	/* Sanity check the packet size */
	if (len > 65535)
		return -EMSGSIZE;
#endif
	size = len + AX25_BPQ_HEADER_LEN + AX25_MAX_HEADER_LEN + ROSE_MIN_LEN; // exp: {{uadd}}

	if ((skb = sock_alloc_send_skb(sk, size, msg->msg_flags & MSG_DONTWAIT, &err)) == NULL) // exp: {{size}}
		return err;

	return len;
}
