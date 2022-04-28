// https://security.snyk.io/vuln/SNYK-UNMANAGED-LIBSNDFILE-2370269
// https://github.com/libsndfile/libsndfile/issues/92

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include <stdlib.h>
#include <stdint.h>

#define	SENSIBLE_SIZE	(0x40000000)

struct SF_VIRTUAL_IO
{	
    int x;
};

typedef struct sf_private_tag
{
	int cpu_flags ;
	/* Virtual I/O functions. */
	int					virtual_io ;
	void				*vio_user_data ;
} SF_PRIVATE ;

size_t __mkint_sink2(void* ptr, size_t c, void* t);

size_t
sys_psf_fwrite (const void *ptr, size_t bytes, size_t items, SF_PRIVATE *psf)
{	
    size_t total = 0;

	if (bytes && items > SIZE_MAX / bytes)
        return NULL;

	if (psf->virtual_io)
		return __mkint_sink2(ptr, bytes*items, psf->virtual_io / bytes) ;

	items *= bytes ;

	return total / bytes ;
} /* psf_fwrite */

