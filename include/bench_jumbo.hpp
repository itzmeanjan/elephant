#pragma once
#include "jumbo.hpp"
#include "utils.hpp"
#include <benchmark/benchmark.h>
#include <cassert>

// Benchmarks Elephant AEAD functions on CPU
namespace bench_elephant {

// Benchmark Jumbo authenticated encryption on CPU system
static void
jumbo_encrypt(benchmark::State& state)
{
  constexpr size_t klen = 16;
  constexpr size_t nlen = 12;
  constexpr size_t tlen = 8;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t* key = static_cast<uint8_t*>(std::malloc(klen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(nlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(tlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ctlen));

  random_data(key, klen);
  random_data(nonce, nlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  for (auto _ : state) {
    jumbo::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  bool f = jumbo::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);
  assert(f);

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr = ctlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * per_itr));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

// Benchmark Jumbo verified decryption on CPU system
static void
jumbo_decrypt(benchmark::State& state)
{
  constexpr size_t klen = 16;
  constexpr size_t nlen = 12;
  constexpr size_t tlen = 8;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t* key = static_cast<uint8_t*>(std::malloc(klen));
  uint8_t* nonce = static_cast<uint8_t*>(std::malloc(nlen));
  uint8_t* tag = static_cast<uint8_t*>(std::malloc(tlen));
  uint8_t* data = static_cast<uint8_t*>(std::malloc(dlen));
  uint8_t* txt = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* enc = static_cast<uint8_t*>(std::malloc(ctlen));
  uint8_t* dec = static_cast<uint8_t*>(std::malloc(ctlen));

  random_data(key, klen);
  random_data(nonce, nlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  jumbo::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

  for (auto _ : state) {
    bool f = jumbo::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);

    benchmark::DoNotOptimize(dec);
    benchmark::DoNotOptimize(f);
    benchmark::ClobberMemory();
  }

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr = ctlen + dlen;
  state.SetBytesProcessed(static_cast<int64_t>(state.iterations() * per_itr));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

}
