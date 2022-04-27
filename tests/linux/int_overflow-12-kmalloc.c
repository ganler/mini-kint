// http://git.kernel.org/linus/30c2235cbc477d4629983d440cdc4f496fec9246
// sctp-2008-3526

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

struct sctp_auth_bytes {
	u32	len;
	u8	data[];
};

struct sys_sctp_auth_bytes *sctp_auth_create_key(u32 key_len, gfp_t gfp)
{
	struct sctp_auth_bytes *key;

#ifdef __PATCH__
	/* Verify that we are not going to overflow INT_MAX */
	if ((INT_MAX - key_len) < sizeof(struct sctp_auth_bytes))
		return NULL;
#endif
	/* Allocate the shared key */
	key = kmalloc(sizeof(struct sctp_auth_bytes) + key_len, gfp); // exp32: {{uadd}}
	if (!key)
		return NULL;

	key->len = key_len;

	return key;
}
