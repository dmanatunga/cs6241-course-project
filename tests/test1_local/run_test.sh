../clang test1_local.cpp -emit-llvm -c -o test1_local.bc
../opt -bounds-checking <test1_local.bc >test1_opt.bc
