../clang -O0 loop.cpp -emit-llvm -c -o loop.bc
../opt -bounds-checking <loop.bc >loop_opt.bc
