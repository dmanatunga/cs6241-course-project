../clang -O0 test1_loop.cpp -emit-llvm -c -o test1_loop.bc
../opt -bounds-checking <test1_loop.bc >test1_opt.bc
