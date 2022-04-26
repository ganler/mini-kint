// http://www.openssh.com/txt/preauth.adv

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include <sys/types.h>
#include <stddef.h>

void     fatal(const char *, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));
u_int    packet_get_int(void);
void    *packet_get_string(u_int *length_ptr);
void    *xmalloc(size_t);

char **sys_input_userauth_info_response()
{
	int i;
	u_int nresp;
	char **response = NULL;
	nresp = packet_get_int();

	if (nresp > 0) {
		response = (char **)xmalloc(nresp * sizeof(char*)); // multiplication may overflow
		for (i = 0; i < nresp; i++)
			response[i] = (char *)packet_get_string(NULL);
	}
	return response;
}
