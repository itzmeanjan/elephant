#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>

// Keccak-f[200] Permutation
namespace keccak {

// Number of rounds of keccak-f[200] permutation applied on state, for Delirium
constexpr size_t ROUNDS = 18;

// keccak-f[200] step mapping function, see section 3.2.1 of SHA3 specification
// https://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
theta(uint8_t* const state)
{
  uint8_t c[5];
  uint8_t d[5];

  for (size_t i = 0; i < 5; i++) {
    const uint8_t t0 = state[i] ^ state[i + 5];
    const uint8_t t1 = state[i + 10] ^ state[i + 15];
    const uint8_t t2 = t0 ^ t1 ^ state[i + 20];

    c[i] = t2;
  }

  for (size_t i = 1; i < 5; i++) {
    d[i] = c[i - 1] ^ std::rotl(c[(i + 1) % 5], 1);
  }

  d[0] = c[4] ^ std::rotl(c[1], 1);

  for (size_t i = 0; i < 5; i++) {
    state[i + 0] ^= d[i];
    state[i + 5] ^= d[i];
    state[i + 10] ^= d[i];
    state[i + 15] ^= d[i];
    state[i + 20] ^= d[i];
  }
}

}
