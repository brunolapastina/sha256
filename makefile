all:
	clang++ -Wall -O3 -std=c++20 -Isrc src/sha256_alg.cpp tst/test.cpp -o sha256test