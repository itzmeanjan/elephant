#pragma once
#include "spongent.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>

// Benchmarks Elephant AEAD functions on CPU
namespace bench_elephant {

// Benchmarks Spongent-π[W] permutation for `rounds` -many rounds | W = slen ∈
// {160, 176}
template<const size_t slen, const size_t rounds>
static void
spongent_permutation(benchmark::State& state)
{
  constexpr size_t sbytes = slen >> 3;

  uint8_t st[sbytes]{};
  random_data(st, sizeof(st));

  for (auto _ : state) {
    spongent::permute<slen, rounds>(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * sbytes));
}

}
