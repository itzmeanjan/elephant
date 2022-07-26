#include "bench_spongent.hpp"

// register Spongent-π[W] for benchmarking
BENCHMARK(bench_elephant::spongent_permutation<160, 1>);
BENCHMARK(bench_elephant::spongent_permutation<160, 80>);
BENCHMARK(bench_elephant::spongent_permutation<176, 1>);
BENCHMARK(bench_elephant::spongent_permutation<176, 90>);

// benchmark runner main function
BENCHMARK_MAIN();
