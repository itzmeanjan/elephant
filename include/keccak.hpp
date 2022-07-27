#pragma once
#include <bit>
#include <cstddef>
#include <cstdint>

// Keccak-f[200] Permutation
namespace keccak {

// Number of rounds of keccak-f[200] permutation applied on state, for Delirium
constexpr size_t ROUNDS = 18;

// Leftwards circular rotation offset of 25 lanes ( each lane is 8 -bit wide )
// of state array, as provided in table 2 below algorithm 2 in section 3.2.2 of
// https://dx.doi.org/10.6028/NIST.FIPS.202
//
// Note, following offsets are obtained by performing % 8 ( bit width of lane )
// on offsets provided in above mentioned link
constexpr size_t ROT[]{ 0 & 7,   1 & 7,   190 & 7, 28 & 7,  91 & 7,
                        36 & 7,  300 & 7, 6 & 7,   55 & 7,  276 & 7,
                        3 & 7,   10 & 7,  171 & 7, 153 & 7, 231 & 7,
                        105 & 7, 45 & 7,  15 & 7,  21 & 7,  136 & 7,
                        210 & 7, 66 & 7,  253 & 7, 120 & 7, 78 & 7 };

// Keccak-f[200] step mapping function, see section 3.2.1 of SHA3 specification
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

// Keccak-f[200] step mapping function, see section 3.2.2 of SHA3 specification
// https://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
rho(uint8_t* const state)
{
  for (size_t i = 0; i < 25; i++) {
    state[i] = std::rotl(state[i], ROT[i]);
  }
}

// Keccak-f[200] step mapping function, see section 3.2.3 of SHA3 specification
// https://dx.doi.org/10.6028/NIST.FIPS.202
inline static void
pi(const uint8_t* const __restrict istate, // input permutation state
   uint8_t* const __restrict ostate        // output permutation state
)
{
  for (size_t i = 0; i < 5; i++) {
    const size_t ix3 = i * 3;
    const size_t ix5 = i * 5;

    for (size_t j = 0; j < 5; j++) {
      ostate[ix5 + j] = istate[5 * j + (ix3 + j) % 5];
    }
  }
}

}
