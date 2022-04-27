// http://git.kernel.org/linus/fcc6cb0c13555e78c2d47257b6d1b5e59b0c419a
// cfg80211-2009-3280

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#ifndef __PATCH__
const u8 *sys_cfg80211_find_ie(u8 eid, const u8 *ies, size_t len)
#else
const u8 *sys_cfg80211_find_ie(u8 eid, const u8 *ies, int len)
#endif
{
	while (len > 2 && ies[0] != eid) {
		len -= ies[1] + 2;	// exp: {{usub}}
		ies += ies[1] + 2;
	}
	if (len < 2)
		return NULL;
	if (len < 2 + ies[1])
		return NULL;
	return ies;
}
