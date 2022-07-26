#pragma once
#include "spongent.hpp"
#include <algorithm>
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

// When authenticating associated data, this routine extracts out requested i-th
// block from {pre, post}-padded associated data.
//
// Note,
//
// - associated data is prepended with 12 -bytes nonce
// - associated data is appended with byte value 1, which might incur zero
// padding
//
// See step 5 of algorithm 1 & 2, in Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
//
// Template parameter `slen` expects value {160, 176}, which is the block length
// of underlying primitive (permutation). When using this function for
//
// - Dumbo, do slen = 160
// - Jumbo, do slen = 176
//
// This implementation collects some inspiration from
// https://github.com/TimBeyne/Elephant/blob/b1a6883/crypto_aead/elephant160v2/ref/encrypt.c#L37-L68
template<const size_t slen>
static void
get_ith_data_block(
  const uint8_t* const __restrict data,  // N -bytes associated data
  const size_t dlen,                     // len(data) = N | >= 0
  const uint8_t* const __restrict nonce, // 12 -bytes public message nonce
  const size_t i,               // index ( zero based ) of block to extract
  uint8_t* const __restrict blk // extracted block to be placed here
  ) requires(spongent::check_state_bit_len(slen))
{
  constexpr size_t blk_len = slen >> 3;
  constexpr uint8_t pad = 0x01;

  size_t off = 0;

  std::memcpy(blk, nonce, 12 * (i == 0));
  off += 12 * (i == 0);

  const size_t doff = i * blk_len - 12 * (i > 0);
  const size_t tot_to_read = blk_len - off;
  const size_t data_to_read = std::min(tot_to_read, dlen - doff);

  std::memcpy(blk + off, data + doff, data_to_read);
  off += data_to_read;

  const size_t rm_to_read = blk_len - off;
  const size_t rd_bytes = std::min(rm_to_read, 1);

  std::memcpy(blk + off, &pad, rd_bytes);
  off += rd_bytes;

  std::memset(blk + off, 0, blk_len - off);
}

}
