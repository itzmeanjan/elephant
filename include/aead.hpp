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

}
