#pragma once
#include "spongent.hpp"
#include <bit>

// Elephant Authenticated Encryption with Associated Data
namespace elephant {

// Updates Spongent-π-[{160, 176}] linear feedback shift register, following
// algorithm provided in section 2.{3, 4}.2 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
template<const size_t slen>
inline static void
lfsr(uint8_t* const x) requires(spongent::check_state_bit_len(slen))
{
  constexpr size_t sbytes = slen >> 3;

  uint8_t tmp;
  if constexpr (slen == 160) {
    tmp = std::rotl(x[0], 3) ^ (x[3] << 7) ^ (x[13] >> 7);
  } else if constexpr (slen == 176) {
    tmp = std::rotl(x[0], 1) ^ (x[3] << 7) ^ (x[19] >> 7);
  }

  for (size_t i = 0; i < sbytes - 1; i++) {
    x[i] = x[i + 1];
  }

  x[sbytes - 1] = tmp;
}

// Computes next `mask(K, a, b)`, which is used for {en, de}crypting {plain,
// cipher} text, authenticating associated data/ cipher text
//
// See section 2.2 & algorithm {1, 2} of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
// where it's described for b = {0, 1, 2}
//
// I suggest you also read section 4.2 of above linked specification, where some
// computational tricks are described which are employed here, making
// implementation more compute friendly.
//
// key   -> previous round's `hmask`; for first round it's permuted secret key
// hmask -> result of applying φ_1^a(key), used as `key` in next round
// fmask -> result of applying φ_2^b(hmask), actual mask used in this round
template<const size_t slen, const size_t b>
inline static void
next_mask(const uint8_t* const __restrict key,
          uint8_t* const __restrict hmask,
          uint8_t* const __restrict fmask,
          const size_t a) requires(spongent::check_state_bit_len(slen))
{
  static_assert((b == 0) || (b == 1) || (b == 2));
  constexpr size_t sbytes = slen >> 3;

  std::memcpy(hmask, key, sbytes);
  lfsr<slen>(hmask);

  if constexpr (b == 0) {
    std::memcpy(fmask, hmask, sbytes);
  } else if constexpr (b == 1) {
    for (size_t i = 0; i < sbytes; i++) {
      fmask[i] = hmask[i] ^ key[i];
    }
  } else if constexpr (b == 2) {
    uint8_t tmp[sbytes]{};

    for (size_t i = 0; i < sbytes; i++) {
      tmp[i] = hmask[i] ^ key[i];
    }

    std::memcpy(fmask, tmp, sbytes);
    lfsr<slen>(fmask);

    for (size_t i = 0; i < sbytes; i++) {
      fmask[i] ^= tmp[i];
    }
  }
}

}
