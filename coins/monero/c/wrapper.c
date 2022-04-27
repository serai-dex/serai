#include "device/device_default.hpp"

#include "ringct/rctSigs.h"

extern "C" {
  void c_hash_to_point(uint8_t* point) {
    rct::key key_point;
    ge_p3 e_p3;
    memcpy(key_point.bytes, point, 32);
    rct::hash_to_p3(e_p3, key_point);
    ge_p3_tobytes(point, &e_p3);
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

    return verRctCLSAGSimple(msg, clsag, keys, pseudo_out);
  }
}
