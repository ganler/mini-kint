; ModuleID = 'int_overflow-3-sys_xdr_array.c'
source_filename = "int_overflow-3-sys_xdr_array.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct._IO_FILE = type { i32, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, i8*, %struct._IO_marker*, %struct._IO_FILE*, i32, i32, i64, i16, i8, [1 x i8], i8*, i64, %struct._IO_codecvt*, %struct._IO_wide_data*, %struct._IO_FILE*, i8*, i64, i32, [20 x i8] }
%struct._IO_marker = type opaque
%struct._IO_codecvt = type opaque
%struct._IO_wide_data = type opaque
%struct.XDR = type { i32, %struct.xdr_ops*, i8*, i8*, i8*, i32 }
%struct.xdr_ops = type { i32 (%struct.XDR*, i64*)*, i32 (%struct.XDR*, i64*)*, i32 (%struct.XDR*, i8*, i32)*, i32 (%struct.XDR*, i8*, i32)*, i32 (%struct.XDR*)*, i32 (%struct.XDR*, i32)*, i32* (%struct.XDR*, i32)*, void (%struct.XDR*)*, i32 (%struct.XDR*, i32*)*, i32 (%struct.XDR*, i32*)* }

@.str = private unnamed_addr constant [7 x i8] c"elsize\00", align 1
@.str.1 = private unnamed_addr constant [31 x i8] c"int_overflow-3-sys_xdr_array.c\00", align 1
@__PRETTY_FUNCTION__.sys_xdr_array = private unnamed_addr constant [73 x i8] c"bool_t sys_xdr_array(XDR *, caddr_t *, u_int *, u_int, u_int, xdrproc_t)\00", align 1
@stderr = external global %struct._IO_FILE*, align 8
@.str.2 = private unnamed_addr constant [26 x i8] c"xdr_array: out of memory\0A\00", align 1

; Function Attrs: noinline nounwind uwtable
define dso_local i32 @sys_xdr_array(%struct.XDR* noundef %0, i8** noundef %1, i32* noundef %2, i32 noundef %3, i32 noundef %4, i32 (%struct.XDR*, i8*, ...)* noundef %5) #0 {
  %7 = alloca i32, align 4
  %8 = alloca %struct.XDR*, align 8
  %9 = alloca i8**, align 8
  %10 = alloca i32*, align 8
  %11 = alloca i32, align 4
  %12 = alloca i32, align 4
  %13 = alloca i32 (%struct.XDR*, i8*, ...)*, align 8
  %14 = alloca i32, align 4
  %15 = alloca i8*, align 8
  %16 = alloca i32, align 4
  %17 = alloca i32, align 4
  %18 = alloca i32, align 4
  store %struct.XDR* %0, %struct.XDR** %8, align 8
  store i8** %1, i8*** %9, align 8
  store i32* %2, i32** %10, align 8
  store i32 %3, i32* %11, align 4
  store i32 %4, i32* %12, align 4
  store i32 (%struct.XDR*, i8*, ...)* %5, i32 (%struct.XDR*, i8*, ...)** %13, align 8
  %19 = load i8**, i8*** %9, align 8
  %20 = load i8*, i8** %19, align 8
  store i8* %20, i8** %15, align 8
  store i32 1, i32* %17, align 4
  %21 = load i32, i32* %12, align 4
  %22 = icmp ne i32 %21, 0
  br i1 %22, label %23, label %24

23:                                               ; preds = %6
  br label %25

24:                                               ; preds = %6
  call void @__assert_fail(i8* noundef getelementptr inbounds ([7 x i8], [7 x i8]* @.str, i64 0, i64 0), i8* noundef getelementptr inbounds ([31 x i8], [31 x i8]* @.str.1, i64 0, i64 0), i32 noundef 33, i8* noundef getelementptr inbounds ([73 x i8], [73 x i8]* @__PRETTY_FUNCTION__.sys_xdr_array, i64 0, i64 0)) #5
  unreachable

25:                                               ; preds = %23
  %26 = load %struct.XDR*, %struct.XDR** %8, align 8
  %27 = load i32*, i32** %10, align 8
  %28 = call i32 @xdr_u_int(%struct.XDR* noundef %26, i32* noundef %27) #6
  %29 = icmp ne i32 %28, 0
  br i1 %29, label %31, label %30

30:                                               ; preds = %25
  store i32 0, i32* %7, align 4
  br label %107

31:                                               ; preds = %25
  %32 = load i32*, i32** %10, align 8
  %33 = load i32, i32* %32, align 4
  store i32 %33, i32* %16, align 4
  %34 = load i32, i32* %16, align 4
  %35 = load i32, i32* %11, align 4
  %36 = icmp ugt i32 %34, %35
  br i1 %36, label %37, label %43

37:                                               ; preds = %31
  %38 = load %struct.XDR*, %struct.XDR** %8, align 8
  %39 = getelementptr inbounds %struct.XDR, %struct.XDR* %38, i32 0, i32 0
  %40 = load i32, i32* %39, align 8
  %41 = icmp ne i32 %40, 2
  br i1 %41, label %42, label %43

42:                                               ; preds = %37
  store i32 0, i32* %7, align 4
  br label %107

43:                                               ; preds = %37, %31
  %44 = load i32, i32* %16, align 4
  %45 = load i32, i32* %12, align 4
  %46 = mul i32 %44, %45
  store i32 %46, i32* %18, align 4
  %47 = load i8*, i8** %15, align 8
  %48 = icmp eq i8* %47, null
  br i1 %48, label %49, label %74

49:                                               ; preds = %43
  %50 = load %struct.XDR*, %struct.XDR** %8, align 8
  %51 = getelementptr inbounds %struct.XDR, %struct.XDR* %50, i32 0, i32 0
  %52 = load i32, i32* %51, align 8
  switch i32 %52, label %72 [
    i32 1, label %53
    i32 2, label %71
  ]

53:                                               ; preds = %49
  %54 = load i32, i32* %16, align 4
  %55 = icmp eq i32 %54, 0
  br i1 %55, label %56, label %57

56:                                               ; preds = %53
  store i32 1, i32* %7, align 4
  br label %107

57:                                               ; preds = %53
  %58 = load i32, i32* %18, align 4
  %59 = zext i32 %58 to i64
  %60 = call noalias i8* @malloc(i64 noundef %59) #6
  store i8* %60, i8** %15, align 8
  %61 = load i8**, i8*** %9, align 8
  store i8* %60, i8** %61, align 8
  %62 = load i8*, i8** %15, align 8
  %63 = icmp eq i8* %62, null
  br i1 %63, label %64, label %67

64:                                               ; preds = %57
  %65 = load %struct._IO_FILE*, %struct._IO_FILE** @stderr, align 8
  %66 = call i32 (%struct._IO_FILE*, i8*, ...) @fprintf(%struct._IO_FILE* noundef %65, i8* noundef getelementptr inbounds ([26 x i8], [26 x i8]* @.str.2, i64 0, i64 0))
  store i32 0, i32* %7, align 4
  br label %107

67:                                               ; preds = %57
  %68 = load i8*, i8** %15, align 8
  %69 = load i32, i32* %18, align 4
  %70 = zext i32 %69 to i64
  call void @llvm.memset.p0i8.i64(i8* align 1 %68, i8 0, i64 %70, i1 false)
  br label %73

71:                                               ; preds = %49
  store i32 1, i32* %7, align 4
  br label %107

72:                                               ; preds = %49
  br label %73

73:                                               ; preds = %72, %67
  br label %74

74:                                               ; preds = %73, %43
  store i32 0, i32* %14, align 4
  br label %75

75:                                               ; preds = %93, %74
  %76 = load i32, i32* %14, align 4
  %77 = load i32, i32* %16, align 4
  %78 = icmp ult i32 %76, %77
  br i1 %78, label %79, label %82

79:                                               ; preds = %75
  %80 = load i32, i32* %17, align 4
  %81 = icmp ne i32 %80, 0
  br label %82

82:                                               ; preds = %79, %75
  %83 = phi i1 [ false, %75 ], [ %81, %79 ]
  br i1 %83, label %84, label %96

84:                                               ; preds = %82
  %85 = load i32 (%struct.XDR*, i8*, ...)*, i32 (%struct.XDR*, i8*, ...)** %13, align 8
  %86 = load %struct.XDR*, %struct.XDR** %8, align 8
  %87 = load i8*, i8** %15, align 8
  %88 = call i32 (%struct.XDR*, i8*, ...) %85(%struct.XDR* noundef %86, i8* noundef %87, i32 noundef 0)
  store i32 %88, i32* %17, align 4
  %89 = load i32, i32* %12, align 4
  %90 = load i8*, i8** %15, align 8
  %91 = zext i32 %89 to i64
  %92 = getelementptr inbounds i8, i8* %90, i64 %91
  store i8* %92, i8** %15, align 8
  br label %93

93:                                               ; preds = %84
  %94 = load i32, i32* %14, align 4
  %95 = add i32 %94, 1
  store i32 %95, i32* %14, align 4
  br label %75, !llvm.loop !6

96:                                               ; preds = %82
  %97 = load %struct.XDR*, %struct.XDR** %8, align 8
  %98 = getelementptr inbounds %struct.XDR, %struct.XDR* %97, i32 0, i32 0
  %99 = load i32, i32* %98, align 8
  %100 = icmp eq i32 %99, 2
  br i1 %100, label %101, label %105

101:                                              ; preds = %96
  %102 = load i8**, i8*** %9, align 8
  %103 = load i8*, i8** %102, align 8
  call void @free(i8* noundef %103) #6
  %104 = load i8**, i8*** %9, align 8
  store i8* null, i8** %104, align 8
  br label %105

105:                                              ; preds = %101, %96
  %106 = load i32, i32* %17, align 4
  store i32 %106, i32* %7, align 4
  br label %107

107:                                              ; preds = %105, %71, %64, %56, %42, %30
  %108 = load i32, i32* %7, align 4
  ret i32 %108
}

; Function Attrs: noreturn nounwind
declare void @__assert_fail(i8* noundef, i8* noundef, i32 noundef, i8* noundef) #1

; Function Attrs: nounwind
declare i32 @xdr_u_int(%struct.XDR* noundef, i32* noundef) #2

; Function Attrs: nounwind
declare noalias i8* @malloc(i64 noundef) #2

declare i32 @fprintf(%struct._IO_FILE* noundef, i8* noundef, ...) #3

; Function Attrs: argmemonly nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #4

; Function Attrs: nounwind
declare void @free(i8* noundef) #2

attributes #0 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { noreturn nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { argmemonly nofree nounwind willreturn writeonly }
attributes #5 = { noreturn nounwind }
attributes #6 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 1}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"Ubuntu clang version 14.0.1-++20220419033222+0fbe860711be-1~exp1~20220419033233.123"}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.mustprogress"}
