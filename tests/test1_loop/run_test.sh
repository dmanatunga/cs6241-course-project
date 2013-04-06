../clang -O0 loop_hoisting.cpp -emit-llvm -c -o loop.bc
../opt -bounds-checking <loop.bc >loop_opt.bc
