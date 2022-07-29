#pragma once
#include "keccak.hpp"
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

// Benchmarks Keccak-f[200] permutation for `rounds` -many rounds
template<const size_t rounds>
static void
keccak_permutation(benchmark::State& state)
{
  uint8_t st[25]{};
  random_data(st, sizeof(st));

  for (auto _ : state) {
    keccak::permute<rounds>(st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * 25));
}

}
