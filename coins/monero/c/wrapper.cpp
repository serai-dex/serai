#include <mutex>

#include "ringct/bulletproofs.h"
#include "ringct/rctSigs.h"

typedef std::lock_guard<std::mutex> lock;

std::mutex rng_mutex;
uint8_t rng_entropy[64];

extern "C" {
  void rng(uint8_t* seed) {
    // Set the first half to the seed
    memcpy(rng_entropy, seed, 32);
    // Set the second half to the hash of a DST to ensure a lack of collisions
    crypto::cn_fast_hash("RNG_entropy_seed", 16, (char*) &rng_entropy[32]);
  }
}

extern "C" void monero_wide_reduce(uint8_t* value);
namespace crypto {
  void generate_random_bytes_not_thread_safe(size_t n, void* value) {
    size_t written = 0;
    while (written != n) {
      uint8_t hash[32];
      crypto::cn_fast_hash(rng_entropy, 64, (char*) hash);
      // Step the RNG by setting the latter half to the most recent result
      // Does not leak the RNG, even if the values are leaked (which they are
      // expected to be) due to the first half remaining constant and
      // undisclosed
      memcpy(&rng_entropy[32], hash, 32);

      size_t next = n - written;
      if (next > 32) {
        next = 32;
      }
      memcpy(&((uint8_t*) value)[written], hash, next);
      written += next;
    }
  }

  void random32_unbiased(unsigned char *bytes) {
    uint8_t value[64];
    generate_random_bytes_not_thread_safe(64, value);
    monero_wide_reduce(value);
    memcpy(bytes, value, 32);
  }
}

extern "C" {
  void c_hash_to_point(uint8_t* point) {
    rct::key key_point;
    ge_p3 e_p3;
    memcpy(key_point.bytes, point, 32);
    rct::hash_to_p3(e_p3, key_point);
    ge_p3_tobytes(point, &e_p3);
  }

  uint8_t* c_generate_bp(uint8_t* seed, uint8_t len, uint64_t* a, uint8_t* m) {
    lock guard(rng_mutex);
    rng(seed);

    rct::keyV masks;
    std::vector<uint64_t> amounts;
    masks.resize(len);
    amounts.resize(len);
    for (uint8_t i = 0; i < len; i++) {
      memcpy(masks[i].bytes, m + (i * 32), 32);
      amounts[i] = a[i];
    }

    rct::Bulletproof bp = rct::bulletproof_PROVE(amounts, masks);

    std::stringstream ss;
    binary_archive<true> ba(ss);
    ::serialization::serialize(ba, bp);
    uint8_t* res = (uint8_t*) calloc(ss.str().size(), 1);
    memcpy(res, ss.str().data(), ss.str().size());
    return res;
  }

  bool c_verify_bp(
    uint8_t* seed,
    uint s_len,
    uint8_t* s,
    uint8_t c_len,
    uint8_t* c
  ) {
    // BPs are batch verified which use RNG based weights to ensure individual
    // integrity
    // That's why this must also have control over RNG, to prevent interrupting
    // multisig signing while not using known seeds. Considering this doesn't
    // actually define a batch, and it's only verifying a single BP,
    // it'd probably be fine, but...
    lock guard(rng_mutex);
    rng(seed);

    rct::Bulletproof bp;
    std::stringstream ss;
    std::string str;
    str.assign((char*) s, (size_t) s_len);
    ss << str;
    binary_archive<false> ba(ss);
    ::serialization::serialize(ba, bp);
    if (!ss.good()) {
      return false;
    }

    bp.V.resize(c_len);
    for (uint8_t i = 0; i < c_len; i++) {
      memcpy(bp.V[i].bytes, &c[i * 32], 32);
    }

    try { return rct::bulletproof_VERIFY(bp); } catch(...) { return false; }
  }

  bool c_verify_clsag(
    uint s_len,
    uint8_t* s,
    uint8_t k_len,
    uint8_t* k,
    uint8_t* I,
    uint8_t* p,
    uint8_t* m
  ) {
    rct::clsag clsag;
    std::stringstream ss;
    std::string str;
    str.assign((char*) s, (size_t) s_len);
    ss << str;
    binary_archive<false> ba(ss);
    ::serialization::serialize(ba, clsag);
    if (!ss.good()) {
      return false;
    }

    rct::ctkeyV keys;
    keys.resize(k_len);
    for (uint8_t i = 0; i < k_len; i++) {
      memcpy(keys[i].dest.bytes, &k[(i * 2) * 32], 32);
      memcpy(keys[i].mask.bytes, &k[((i * 2) + 1) * 32], 32);
    }

    memcpy(clsag.I.bytes, I, 32);

    rct::key pseudo_out;
    memcpy(pseudo_out.bytes, p, 32);

    rct::key msg;
    memcpy(msg.bytes, m, 32);

    try {
      return verRctCLSAGSimple(msg, clsag, keys, pseudo_out);
    } catch(...) { return false; }
  }
}
