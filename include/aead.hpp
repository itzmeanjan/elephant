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
next_mask(
  const uint8_t* const __restrict key,
  uint8_t* const __restrict hmask,
  uint8_t* const __restrict fmask) requires(spongent::check_state_bit_len(slen))
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
// Template parameter `slen` expects value {160, 176}, which is the block bit
// length of underlying primitive (permutation). When using this function for
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
  const size_t rd_bytes = std::min(rm_to_read, 1ul);

  std::memcpy(blk + off, &pad, rd_bytes);
  off += rd_bytes;

  std::memset(blk + off, 0, blk_len - off);
}

// When authenticating cipher text, this routine extracts out requested i-th
// block from padded cipher text.
//
// Note, cipher text is appended with byte value 1, which might also incur zero
// padding
//
// See step 6 of algorithm 1 & 2, in Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
//
// Template parameter `slen` expects value {160, 176}, which is the block bit
// length of underlying primitive (permutation). When using this function for
//
// - Dumbo, do slen = 160
// - Jumbo, do slen = 176
//
// This implementation collects some inspiration from
// https://github.com/TimBeyne/Elephant/blob/b1a6883/crypto_aead/elephant160v2/ref/encrypt.c#L70-L91
template<const size_t slen>
static void
get_ith_cipher_block(
  const uint8_t* const __restrict cipher, // N -bytes cipher text
  const size_t ctlen,                     // len(cipher) = N | >= 0
  const size_t i,               // index ( zero based ) of block to extract
  uint8_t* const __restrict blk // extracted block to be placed here
  ) requires(spongent::check_state_bit_len(slen))
{
  constexpr size_t blk_len = slen >> 3;
  constexpr uint8_t pad = 0x01;

  size_t off = 0;

  const size_t coff = i * blk_len;
  const size_t tot_to_read = blk_len - off;
  const size_t cipher_to_read = std::min(tot_to_read, ctlen - coff);

  std::memcpy(blk + off, cipher + coff, cipher_to_read);
  off += cipher_to_read;

  const size_t rm_to_read = blk_len - off;
  const size_t rd_bytes = std::min(rm_to_read, 1ul);

  std::memcpy(blk + off, &pad, rd_bytes);
  off += rd_bytes;

  std::memset(blk + off, 0, blk_len - off);
}

// Given 16 -bytes secret key, 12 -bytes public message nonce, N -bytes
// associated data & M -bytes plain text, this routine computes M -bytes
// encrypted text & 8 -bytes authentication tag, using Dumbo/ Jumbo AEAD scheme
// | M, N >= 0
//
// Note, associated data is never encrypted, but only authenticated.
// Also avoid reusing same nonce under same key.
//
// See algorithm 1 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
template<const size_t slen, const size_t rounds>
static void
encrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 96 -bit nonce
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) = N | >= 0
        const uint8_t* const __restrict txt,   // M -bytes plain text
        uint8_t* const __restrict enc,         // M -bytes encrypted text
        const size_t ctlen,                    // len(txt) = len(enc) = M | >= 0
        uint8_t* const __restrict tag          // 64 -bit authentication tag
)
{
  constexpr size_t sbytes = slen >> 3;

  uint8_t ekey[sbytes]{};
  uint8_t hmask[sbytes]{};
  uint8_t fmask[sbytes]{};

  // begin encryption

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  uint8_t enonce[sbytes]{};

  size_t off = 0;
  while (off < ctlen) {
    const size_t elen = std::min(sbytes, ctlen - off);

    std::memcpy(enonce, nonce, 12);
    std::memset(enonce + 12, 0, sizeof(enonce) - 12);

    next_mask<slen, 1>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t i = 0; i < sbytes; i++) {
      enonce[i] ^= fmask[i];
    }

    spongent::permute<slen, rounds>(enonce);

    for (size_t i = 0; i < sbytes; i++) {
      enonce[i] ^= fmask[i];
    }

    for (size_t i = 0; i < elen; i++) {
      enc[off + i] = txt[off + i] ^ enonce[i];
    }

    off += elen;
  }

  // end encryption

  // begin authentication of associated data

  constexpr size_t br[]{ 0, 1 };

  uint8_t tag_[sbytes]{};
  uint8_t msg_blk[sbytes]{};

  const size_t padded_data_len = 12 + dlen + 1;
  const size_t full_blk_cnt0 = padded_data_len / sbytes;
  const size_t rm_bytes0 = padded_data_len % sbytes;
  const size_t tot_blk_cnt0 = full_blk_cnt0 + br[rm_bytes0 > 0];

  get_ith_data_block<slen>(data, dlen, nonce, 0, tag_);

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 1; i < tot_blk_cnt0; i++) {
    get_ith_data_block<slen>(data, dlen, nonce, i, msg_blk);

    next_mask<slen, 0>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<slen, rounds>(msg_blk);

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < sbytes; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of associated data

  // begin authentication of cipher text

  const size_t padded_cipher_len = ctlen + 1;
  const size_t full_blk_cnt1 = padded_cipher_len / sbytes;
  const size_t rm_bytes1 = padded_cipher_len % sbytes;
  const size_t tot_blk_cnt1 = full_blk_cnt1 + br[rm_bytes1 > 0];

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 0; i < tot_blk_cnt1; i++) {
    get_ith_cipher_block<slen>(enc, ctlen, i, msg_blk);

    next_mask<slen, 2>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<slen, rounds>(msg_blk);

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < sbytes; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of cipher text

  // begin step 12 of algorithm 1, 2

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 0; i < sbytes; i++) {
    tag_[i] ^= ekey[i];
  }

  spongent::permute<slen, rounds>(tag_);

  for (size_t i = 0; i < sbytes; i++) {
    tag_[i] ^= ekey[i];
  }

  // end step 12 of algorithm 1, 2

  std::memcpy(tag, tag_, 8);
}

// Given 16 -bytes secret key, 12 -bytes public message nonce, 8 -bytes
// authentication tag, N -bytes associated data & M -bytes encrypted text, this
// routine computes M -bytes plain text & boolean verification flag, using
// Dumbo/ Jumbo AEAD scheme | M, N >= 0
//
// Note, M -bytes plain text is released only when authentication passes i.e.
// boolean verification flag holds truth value. Otherwise one should find zero
// values in decrypted plain text.
//
// See algorithm 2 of Elephant specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
template<const size_t slen, const size_t rounds>
static bool
decrypt(const uint8_t* const __restrict key,   // 128 -bit secret key
        const uint8_t* const __restrict nonce, // 96 -bit nonce
        const uint8_t* const __restrict tag,   // 64 -bit authentication tag
        const uint8_t* const __restrict data,  // N -bytes associated data
        const size_t dlen,                     // len(data) = N | >= 0
        const uint8_t* const __restrict enc,   // M -bytes encrypted text
        uint8_t* const __restrict txt,         // M -bytes plain text
        const size_t ctlen                     // len(enc) = len(txt) = M | >= 0
)
{
  constexpr size_t sbytes = slen >> 3;

  uint8_t ekey[sbytes]{};
  uint8_t hmask[sbytes]{};
  uint8_t fmask[sbytes]{};

  // begin decryption

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  uint8_t enonce[sbytes]{};

  size_t off = 0;
  while (off < ctlen) {
    const size_t elen = std::min(sbytes, ctlen - off);

    std::memcpy(enonce, nonce, 12);
    std::memset(enonce + 12, 0, sizeof(enonce) - 12);

    elephant::next_mask<slen, 1>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t i = 0; i < sbytes; i++) {
      enonce[i] ^= fmask[i];
    }

    spongent::permute<slen, rounds>(enonce);

    for (size_t i = 0; i < sbytes; i++) {
      enonce[i] ^= fmask[i];
    }

    for (size_t i = 0; i < elen; i++) {
      txt[off + i] = enc[off + i] ^ enonce[i];
    }

    off += elen;
  }

  // end decryption

  // begin authentication of associated data

  constexpr size_t br[]{ 0, 1 };

  uint8_t tag_[sbytes]{};
  uint8_t msg_blk[sbytes]{};

  const size_t padded_data_len = 12 + dlen + 1;
  const size_t full_blk_cnt0 = padded_data_len / sbytes;
  const size_t rm_bytes0 = padded_data_len % sbytes;
  const size_t tot_blk_cnt0 = full_blk_cnt0 + br[rm_bytes0 > 0];

  elephant::get_ith_data_block<slen>(data, dlen, nonce, 0, tag_);

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 1; i < tot_blk_cnt0; i++) {
    elephant::get_ith_data_block<slen>(data, dlen, nonce, i, msg_blk);

    elephant::next_mask<slen, 0>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<slen, rounds>(msg_blk);

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < sbytes; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of associated data

  // begin authentication of cipher text

  const size_t padded_cipher_len = ctlen + 1;
  const size_t full_blk_cnt1 = padded_cipher_len / sbytes;
  const size_t rm_bytes1 = padded_cipher_len % sbytes;
  const size_t tot_blk_cnt1 = full_blk_cnt1 + br[rm_bytes1 > 0];

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 0; i < tot_blk_cnt1; i++) {
    elephant::get_ith_cipher_block<slen>(enc, ctlen, i, msg_blk);

    elephant::next_mask<slen, 2>(ekey, hmask, fmask);
    std::memcpy(ekey, hmask, sizeof(hmask));

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    spongent::permute<slen, rounds>(msg_blk);

    for (size_t j = 0; j < sbytes; j++) {
      msg_blk[j] ^= fmask[j];
    }

    for (size_t j = 0; j < sbytes; j++) {
      tag_[j] ^= msg_blk[j];
    }
  }

  // end authentication of cipher text

  // begin step 12 of algorithm 1, 2

  std::memset(ekey, 0, sizeof(ekey));
  std::memcpy(ekey, key, 16);

  spongent::permute<slen, rounds>(ekey);

  for (size_t i = 0; i < sbytes; i++) {
    tag_[i] ^= ekey[i];
  }

  spongent::permute<slen, rounds>(tag_);

  for (size_t i = 0; i < sbytes; i++) {
    tag_[i] ^= ekey[i];
  }

  // end step 12 of algorithm 1, 2

  // compare authentication tag and decide whether to release plain text
  bool flg = false;

  for (size_t i = 0; i < 8; i++) {
    flg |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  std::memset(txt, 0, ctlen * flg);
  return !flg;
}

}
