#include "device/device_default.hpp"

#include "ringct/bulletproofs.h"
#include "ringct/rctSigs.h"

extern "C" {
  void c_hash_to_point(uint8_t* point) {
    rct::key key_point;
    ge_p3 e_p3;
    memcpy(key_point.bytes, point, 32);
    rct::hash_to_p3(e_p3, key_point);
    ge_p3_tobytes(point, &e_p3);
  }

  uint8_t* c_generate_bp(uint8_t len, uint64_t* a, uint8_t* m) {
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
    uint8_t* res = (uint8_t*) calloc(2 + ss.str().size(), 1); // malloc would also work
    memcpy(res + 2, ss.str().data(), ss.str().size());
    res[0] = ss.str().size() >> 8;
    res[1] = ss.str().size() & 255;
    return res;
  }

  bool c_verify_bp(uint s_len, uint8_t* s, uint8_t c_len, uint8_t* c) {
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

  bool c_verify_clsag(uint s_len, uint8_t* s, uint8_t* I, uint8_t k_len, uint8_t* k, uint8_t* m, uint8_t* p) {
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
    memcpy(clsag.I.bytes, I, 32);

    rct::key msg;
    memcpy(msg.bytes, m, 32);

    rct::ctkeyV keys;
    keys.resize(k_len);
    for (uint8_t i = 0; i < k_len; i++) {
      memcpy(keys[i].dest.bytes, &k[(i * 2) * 32], 32);
      memcpy(keys[i].mask.bytes, &k[((i * 2) + 1) * 32], 32);
    }

    rct::key pseudo_out;
    memcpy(pseudo_out.bytes, p, 32);

    try { return verRctCLSAGSimple(msg, clsag, keys, pseudo_out); } catch(...) { return false; }
  }
}
