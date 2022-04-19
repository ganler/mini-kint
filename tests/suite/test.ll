; ModuleID = 'int_overflow-2.c'
source_filename = "int_overflow-2.c"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx12.0.0"

; Function Attrs: noinline nounwind optnone ssp uwtable
define i8** @input_userauth_info_response() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i8**, align 8
  store i8** null, i8*** %3, align 8
  %4 = call i32 @packet_get_int()
  store i32 %4, i32* %2, align 4
  %5 = load i32, i32* %2, align 4
  %6 = icmp ugt i32 %5, 0
  br i1 %6, label %7, label %27

7:                                                ; preds = %0
  %8 = load i32, i32* %2, align 4
  %9 = zext i32 %8 to i64
  %10 = mul i64 %9, 8,                             !mkint.err !0
  %11 = call i8* @xmalloc(i64 %10)
  %12 = bitcast i8* %11 to i8**
  store i8** %12, i8*** %3, align 8
  store i32 0, i32* %1, align 4
  br label %13

13:                                               ; preds = %23, %7
  %14 = load i32, i32* %1, align 4
  %15 = load i32, i32* %2, align 4
  %16 = icmp ult i32 %14, %15
  br i1 %16, label %17, label %26

17:                                               ; preds = %13
  %18 = call i8* @packet_get_string(i32* null)
  %19 = load i8**, i8*** %3, align 8
  %20 = load i32, i32* %1, align 4
  %21 = sext i32 %20 to i64
  %22 = getelementptr inbounds i8*, i8** %19, i64 %21
  store i8* %18, i8** %22, align 8
  br label %23

23:                                               ; preds = %17
  %24 = load i32, i32* %1, align 4
  %25 = add nsw i32 %24, 1
  store i32 %25, i32* %1, align 4
  br label %13, !llvm.loop !10

26:                                               ; preds = %13
  br label %27

27:                                               ; preds = %26, %0
  %28 = load i8**, i8*** %3, align 8
  ret i8** %28
}

declare i32 @packet_get_int() #1

declare i8* @xmalloc(i64) #1

declare i8* @packet_get_string(i32*) #1

attributes #0 = { noinline nounwind optnone ssp uwtable "frame-pointer"="non-leaf" "min-legal-vector-width"="0" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+crc,+crypto,+dotprod,+fp-armv8,+fp16fml,+fullfp16,+lse,+neon,+ras,+rcpc,+rdm,+sha2,+sha3,+sm4,+v8.5a,+zcm,+zcz" }
attributes #1 = { "frame-pointer"="non-leaf" "no-trapping-math"="true" "probe-stack"="__chkstk_darwin" "stack-protector-buffer-size"="8" "target-cpu"="apple-m1" "target-features"="+aes,+crc,+crypto,+dotprod,+fp-armv8,+fp16fml,+fullfp16,+lse,+neon,+ras,+rcpc,+rdm,+sha2,+sha3,+sm4,+v8.5a,+zcm,+zcz" }

!llvm.module.flags = !{!0, !1, !2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = !{i32 2, !"SDK Version", [2 x i32] [i32 12, i32 3]}
!1 = !{i32 1, !"wchar_size", i32 4}
!2 = !{i32 1, !"branch-target-enforcement", i32 0}
!3 = !{i32 1, !"sign-return-address", i32 0}
!4 = !{i32 1, !"sign-return-address-all", i32 0}
!5 = !{i32 1, !"sign-return-address-with-bkey", i32 0}
!6 = !{i32 7, !"PIC Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 1}
!8 = !{i32 7, !"frame-pointer", i32 1}
!9 = !{!"Apple clang version 13.1.6 (clang-1316.0.21.2)"}
!10 = distinct !{!10, !11}
!11 = !{!"llvm.loop.mustprogress"}
