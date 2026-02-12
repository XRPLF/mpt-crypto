#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Crypto and Utility Headers
#include "secp256k1_mpt.h"
#include "utility/mpt_utility.h"

using Buffer = std::vector<unsigned char>;

[[noreturn]] void Throw(char const *s) { throw std::runtime_error(s); }

Buffer hexToBuffer(const std::string &hex) {
  if (hex.length() % 2 != 0)
    Throw("Hex string has odd length.");
  Buffer buffer;
  for (size_t i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    // std::stoul converts the hex string (base 16) to an unsigned long
    unsigned char byte = (unsigned char)std::stoul(byteString, nullptr, 16);
    buffer.push_back(byte);
  }
  return buffer;
}

std::string bufferToHex(const Buffer &buffer) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0');
  for (unsigned char b : buffer)
    ss << std::setw(2) << static_cast<int>(b);
  return ss.str();
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  1. Generate Key Pair:     " << argv[0] << " gen-keypair"
              << std::endl;
    std::cerr << "  2. Generate Blinding Factor: " << argv[0]
              << " gen-blinding-factor" << std::endl;
    std::cerr << "  3. Encrypt Amount:        " << argv[0]
              << " encrypt <AMOUNT> <PUBKEY_64_HEX> <BLINDING_32_HEX>"
              << std::endl;
    std::cerr << "  4. Decrypt Amount:        " << argv[0]
              << " decrypt <CIPHERTEXT_66_HEX> <PRIVKEY_32_HEX>" << std::endl;
    std::cerr << "  5. Convert Hash:          " << argv[0]
              << " gen-convert-hash <ACC_HEX> <SEQ> <ISSUANCE_HEX> <AMOUNT>"
              << std::endl;
    std::cerr << "  6. Convert Proof:         " << argv[0]
              << " gen-convert-proof <PUBKEY_64_HEX> <PRIVKEY_32_HEX> "
                 "<CTX_HASH_32_HEX>"
              << std::endl;

    return 1;
  }

  try {
    std::string command = argv[1];

    // --- MODE 1: GENERATE KEY PAIR ---
    if (command == "gen-keypair") {
      uint8_t privKey[size_privkey];
      uint8_t pubKey[size_pubkey];

      if (mpt_generate_keypair(privKey, pubKey) != 0) {
        Throw("Failed to generate key pair via mpt_generate_keypair");
      }

      std::cout << "{\"generated_keys\":{"
                << "\"public_key\":\""
                << bufferToHex(Buffer(pubKey, pubKey + size_pubkey)) << "\","
                << "\"private_key\":\""
                << bufferToHex(Buffer(privKey, privKey + size_privkey)) << "\""
                << "}}" << std::endl;
      return 0;
    }

    // --- MODE 2: GENERATE BLINDING FACTOR ---
    else if (command == "gen-blinding-factor") {
      uint8_t bf[size_blinding_factor];

      if (mpt_generate_blinding_factor(bf) != 0)
        Throw("Failed to generate blinding factor");

      std::cout << "{\"blinding_factor\":\""
                << bufferToHex(Buffer(bf, bf + size_blinding_factor)) << "\"}"
                << std::endl;
      return 0;
    }

    // --- MODE 3: ENCRYPT AMOUNT ---
    else if (command == "encrypt") {
      if (argc != 5)
        Throw("usage: encrypt <amount> <pubkey_hex> <blinding_hex>");

      uint64_t amount = std::stoull(argv[2]);
      Buffer pubkey_buf = hexToBuffer(argv[3]);
      Buffer blinding_buf = hexToBuffer(argv[4]);

      if (pubkey_buf.size() != size_pubkey)
        Throw("public key must be 64 bytes");
      if (blinding_buf.size() != size_blinding_factor)
        Throw("blinding factor must be 32 bytes");

      uint8_t ciphertext[size_gamal_ciphertext_total];

      if (mpt_encrypt_amount(amount, pubkey_buf.data(), blinding_buf.data(),
                             ciphertext) != 0)
        Throw("encryption failed via mpt_encrypt_amount");

      std::cout << "{\"ciphertext\":\""
                << bufferToHex(Buffer(ciphertext,
                                      ciphertext + size_gamal_ciphertext_total))
                << "\"}" << std::endl;
      return 0;
    }

    // --- MODE 4: DECRYPT AMOUNT ---
    else if (command == "decrypt") {
      if (argc != 4)
        Throw("usage: decrypt <ciphertext_hex> <privkey_hex>");

      Buffer ciphertext_buf = hexToBuffer(argv[2]);
      Buffer privkey_buf = hexToBuffer(argv[3]);

      if (ciphertext_buf.size() != size_gamal_ciphertext_total)
        Throw("ciphertext must be 66 bytes");
      if (privkey_buf.size() != size_privkey)
        Throw("private key must be 32 bytes");

      uint64_t out_amount = 0;

      if (mpt_decrypt_amount(ciphertext_buf.data(), privkey_buf.data(),
                             &out_amount) != 0)
        Throw("decryption failed via mpt_decrypt_amount");

      std::cout << "{\"decrypted_amount\":" << out_amount << "}" << std::endl;
      return 0;
    }

    // --- MODE 5: GENERATE CONVERT HASH ---
    else if (command == "gen-convert-hash") {
      if (argc != 6)
        Throw("usage: gen-convert-hash <acc_id_hex> <seq> <iss_id_hex> <amount>");

      account_id acc;
      Buffer acc_buf = hexToBuffer(argv[2]);
      if (acc_buf.size() != size_acc) Throw("account_id must be 20 bytes");
      std::memcpy(acc.bytes, acc_buf.data(), size_acc);

      uint32_t seq = static_cast<uint32_t>(std::stoul(argv[3]));

      mpt_issuance_id iss;
      Buffer iss_buf = hexToBuffer(argv[4]);
      if (iss_buf.size() != size_iss) Throw("issuance_id must be 24 bytes");
      std::memcpy(iss.bytes, iss_buf.data(), size_iss);

      uint64_t amount = std::stoull(argv[5]);

      uint8_t out_hash[size_half_sha];
      if (mpt_get_convert_context_hash(acc, seq, iss, amount, out_hash) != 0) {
        Throw("failed to generate convert context hash");
      }

      std::cout << "{\"convert_hash\":\"" 
                << bufferToHex(Buffer(out_hash, out_hash + size_half_sha)) 
                << "\"}" << std::endl;
      return 0;
    }

    // --- MODE 6: GENERATE CONVERT PROOF ---
    else if (command == "gen-convert-proof") {
      if (argc != 5)
        Throw("usage: gen-convert-proof <pubkey_hex> <privkey_hex> "
              "<ctx_hash_hex>");

      Buffer pubkey_buf = hexToBuffer(argv[2]);
      Buffer privkey_buf = hexToBuffer(argv[3]);
      Buffer ctx_hash_buf = hexToBuffer(argv[4]);

      if (pubkey_buf.size() != size_pubkey)
        Throw("public key must be 64 bytes");
      if (privkey_buf.size() != size_privkey)
        Throw("private key must be 32 bytes");
      if (ctx_hash_buf.size() != size_half_sha)
        Throw("context hash must be 32 bytes");

      uint8_t out_proof[size_schnorr_proof];
      if (mpt_get_convert_proof(pubkey_buf.data(), privkey_buf.data(),
                                ctx_hash_buf.data(), out_proof) != 0) {
        Throw("failed to generate convert proof via mpt_get_convert_proof");
      }

      std::cout << "{\"convert_proof\":\""
                << bufferToHex(
                       Buffer(out_proof, out_proof + size_schnorr_proof))
                << "\"}" << std::endl;
      return 0;
    }

    else {
      std::cerr << "Invalid command: " << command << std::endl;
      return 1;
    }

  } catch (const std::exception &e) {
    std::cerr << "Runtime Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}