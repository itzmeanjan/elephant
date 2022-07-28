#include "bench_elephant.hpp"

// register Spongent-π[W] for benchmarking
BENCHMARK(bench_elephant::spongent_permutation<160, 1>);
BENCHMARK(bench_elephant::spongent_permutation<160, 80>);
BENCHMARK(bench_elephant::spongent_permutation<176, 1>);
BENCHMARK(bench_elephant::spongent_permutation<176, 90>);

// register Keccak-f[200] for benchmarking
BENCHMARK(bench_elephant::keccak_permutation<1>);
BENCHMARK(bench_elephant::keccak_permutation<18>);

// register Dumbo AEAD for benchmarking
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::dumbo_encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_elephant::dumbo_decrypt)->Args({ 32, 4096 });

// register Jumbo AEAD for benchmarking
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::jumbo_encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_elephant::jumbo_decrypt)->Args({ 32, 4096 });

// register Delirium AEAD for benchmarking
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 64 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 128 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 256 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 512 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 1024 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 2048 });
BENCHMARK(bench_elephant::delirium_encrypt)->Args({ 32, 4096 });
BENCHMARK(bench_elephant::delirium_decrypt)->Args({ 32, 4096 });

// benchmark runner main function
BENCHMARK_MAIN();
