// http://www.kb.cert.org/vuls/id/192995


// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rpc/types.h>
#include <rpc/xdr.h>

bool_t
sys_xdr_array(XDR *xdrs,
	caddr_t *addrp,		/* array pointer */
	u_int *sizep,		/* number of elements */
	u_int maxsize,		/* max numberof elements */
	u_int elsize,		/* size in bytes of each element */
	xdrproc_t elproc)	/* xdr routine to handle each element */
{
	u_int i;
	caddr_t target = *addrp;
	u_int c;  /* the actual element count */
	bool_t stat = TRUE;
	u_int nodesize;

	assert(elsize);
	/* like strings, arrays are really counted arrays */
	if (!xdr_u_int(xdrs, sizep)) {
		return (FALSE);
	}
	c = *sizep;
	if ((c > maxsize) && (xdrs->x_op != XDR_FREE)) {
		return (FALSE);
	}

	nodesize = c * elsize; // multiplication may overflow

	/*
	 * if we are deserializing, we may need to allocate an array.
	 * We also save time by checking for a null array if we are freeing.
	 */
	if (target == NULL)
		switch (xdrs->x_op) {
		case XDR_DECODE:
			if (c == 0)
				return (TRUE);
			*addrp = target = (caddr_t)mem_alloc(nodesize);
			if (target == NULL) {
				(void) fprintf(stderr, 
					"xdr_array: out of memory\n");
				return (FALSE);
			}
			bzero(target, nodesize);
			break;

		case XDR_FREE:
			return (TRUE);

		default: break;
	}
	
	/*
	 * now we xdr each element of array
	 */
	for (i = 0; (i < c) && stat; i++) {
		stat = (*elproc)(xdrs, target, 0);
		target += elsize;
	}

	/*
	 * the array may need freeing
	 */
	if (xdrs->x_op == XDR_FREE) {
		mem_free(*addrp, nodesize);
		*addrp = NULL;
	}
	return (stat);
}
