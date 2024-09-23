#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pkey.h>

extern std::string bignum_to_raw_string(const BIGNUM *bn);
extern std::string extract_pub_key(EVP_PKEY *pkey);
extern std::string extract_priv_key(EVP_PKEY *pkey);
extern std::string base64_url_encode(const std::string &data);

// Test for bignum_to_raw_string
TEST(CryptoHelpersTest, BignumToRawString) {
    BIGNUM *bn = BN_new();
    ASSERT_TRUE(BN_set_word(bn, 0xAABBCCDD));
    
    std::string raw = bignum_to_raw_string(bn);
    // Expected result needs to be determined based on the implementation details
    ASSERT_EQ(raw, "\xDD\xCC\xBB\xAA");  // depending on endianess and BN internal representation
    
    BN_free(bn);
}

// Test for extract_pub_key
TEST(CryptoHelpersTest, ExtractPubKey) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BN_set_word(n, RSA_F4);  // Use a large prime for the public modulus
    BN_set_word(e, 65537);   // Common public exponent
    RSA_set0_key(rsa, n, e, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);

    std::string pubkey = extract_pub_key(pkey);
    ASSERT_TRUE(pubkey.find("-----BEGIN PUBLIC KEY-----") != std::string::npos);
    
    EVP_PKEY_free(pkey);
}

// Test for extract_priv_key
TEST(CryptoHelpersTest, ExtractPrivKey) {
    // Setup similar to ExtractPubKey
}

// Test for base64_url_encode
TEST(CryptoHelpersTest, Base64UrlEncode) {
    std::string raw = "Test string";
    std::string encoded = base64_url_encode(raw);
    ASSERT_EQ(encoded, "VGVzdCBzdHJpbmc");  // Check against a known good base64 URL-encoded string
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
