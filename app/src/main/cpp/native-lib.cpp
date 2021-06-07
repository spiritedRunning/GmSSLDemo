#include <jni.h>
#include <string>
#include <malloc.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sm2.h>
#include <openssl/sms4.h>
#include <crypto/ec/ec_lcl.h>
#include <openssl/aes.h>
#include <crypto/sm2/sm2_lcl.h>
#include "utils.h"
#include <syslog.h>
#include <openssl/pem.h>
#include "log.h"

using std::string;

char *path;

//获取sm2的密钥
EC_KEY *getEcKey() {
    std::string p1 = path;
    p1.append("/private");

    std::string p2 = path;
    p2.append("/public");

    char *privateChar = (char *) malloc(1024);
    memset(privateChar, 0, 1024);
    readBufFromFile((char *) p1.c_str(), privateChar);

    char *publicChar = (char *) malloc(1024);
    memset(publicChar, 0, 1024);
    readBufFromFile((char *) p2.c_str(), publicChar);

    EC_KEY *ec_key;
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    BN_CTX *ctx1 = BN_CTX_new();
    EC_POINT *pubkey_point = EC_POINT_hex2point(ec_key->group, publicChar, NULL, ctx1);
    int iret = EC_KEY_set_public_key(ec_key, pubkey_point);
    BIGNUM *bn_prikey = BN_new();
    iret = BN_hex2bn(&bn_prikey, privateChar);
    iret = EC_KEY_set_private_key(ec_key, bn_prikey);
    p1.clear();
    p2.clear();
    free(publicChar);
    free(privateChar);
    BN_free(bn_prikey);
    EC_POINT_free(pubkey_point);
    return ec_key;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_aesEnc(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length,
                                               jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = AES_BLOCK_SIZE - length % AES_BLOCK_SIZE;
    int block = length / AES_BLOCK_SIZE;
    int endLen = AES_BLOCK_SIZE - pading;

    unsigned char *p = (unsigned char *) malloc(AES_BLOCK_SIZE + 1);
    memset(p, 0, AES_BLOCK_SIZE + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * AES_BLOCK_SIZE, (size_t) endLen);

    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        AES_encrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    AES_encrypt(p, out + block * AES_BLOCK_SIZE, &aes_key);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_aesDec(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length,
                                               jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char *) key, 16 * 8, &aes_key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        AES_decrypt((const unsigned char *) (in + (i * AES_BLOCK_SIZE)),
                    out + i * AES_BLOCK_SIZE,
                    &aes_key);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sha1(JNIEnv *env,
                                             jobject instance,
                                             jbyteArray in_,
                                             jint length) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);

    unsigned char *sha1Msg = (unsigned char *) malloc(SHA_DIGEST_LENGTH + 1);
    memset(sha1Msg, 0, SHA_DIGEST_LENGTH + 1);

    SHA1((const unsigned char *) in, length, sha1Msg);

    jbyteArray array = env->NewByteArray(SHA_DIGEST_LENGTH);
    env->SetByteArrayRegion(array, 0, SHA_DIGEST_LENGTH, (const jbyte *) sha1Msg);

    free(sha1Msg);
    env->ReleaseByteArrayElements(in_, in, 0);

    return array;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_gmssldemo_MainActivity_genSM2KeyPairs(JNIEnv *env,
                                                       jobject instance,
                                                       jstring path_) {

    const char *p = env->GetStringUTFChars(path_, JNI_FALSE);
    int pLen = env->GetStringUTFLength(path_);

    path = (char *) malloc(pLen + 1);
    memset(path, 0, pLen + 1);
    memcpy(path, p, pLen);

    std::string p1 = path;
    p1.append("/private");
    LOGI("private key path: %s", p1.c_str());

    std::string p2 = path;
    p2.append("/public");
    LOGI("public key path: %s", p2.c_str());

    EC_KEY *ec_key = EC_KEY_new();
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_generate_key(ec_key);
    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
    char *publicChar = EC_POINT_point2hex(EC_KEY_get0_group(ec_key),
                                          point,
                                          POINT_CONVERSION_UNCOMPRESSED,
                                          BN_CTX_new());
    const BIGNUM *privateKey = EC_KEY_get0_private_key(ec_key);
    char *privateChar = BN_bn2hex(privateKey);

    int iRet = writeBufToFile((char *) p1.c_str(), privateChar);
    LOGI("private key create result: %d", iRet);

    iRet = writeBufToFile((char *) p2.c_str(), publicChar);
    LOGI("public key create result: %d", iRet);

    EC_KEY_free(ec_key);
    return 0;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm3(JNIEnv *env,
                                            jobject instance,
                                            jbyteArray in_,
                                            jint length) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);

    unsigned char *sm3Msg = (unsigned char *) malloc(SM3_DIGEST_LENGTH + 1);
    memset(sm3Msg, 0, SM3_DIGEST_LENGTH + 1);

    sm3((const unsigned char *) in, length, sm3Msg);

    jbyteArray array = env->NewByteArray(SM3_DIGEST_LENGTH);
    env->SetByteArrayRegion(array, 0, SM3_DIGEST_LENGTH, (const jbyte *) sm3Msg);

    free(sm3Msg);
    env->ReleaseByteArrayElements(in_, in, 0);

    return array;
}



extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm4Enc(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length,
                                               jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    int pading = SMS4_KEY_LENGTH - length % SMS4_KEY_LENGTH;
    int block = length / SMS4_KEY_LENGTH;
    int endLen = SMS4_KEY_LENGTH - pading;

    unsigned char *p = (unsigned char *) malloc(SMS4_KEY_LENGTH + 1);
    memset(p, 0, SMS4_KEY_LENGTH + 1);
    memset(p + endLen, pading, (size_t) pading);
    memcpy(p, in + block * SMS4_KEY_LENGTH, (size_t) endLen);

    sms4_key_t sms4EncKey;
    sms4_set_encrypt_key(&sms4EncKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc((size_t) (length + pading + 1));
    memset(out, 0, (size_t) (length + pading + 1));

    for (int i = 0; i < block; i++) {
        sms4_encrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4EncKey);
    }
    sms4_encrypt(p, out + block * 16, &sms4EncKey);

    jbyteArray array = env->NewByteArray(length + pading);
    env->SetByteArrayRegion(array, 0, length + pading, (const jbyte *) out);

    free(p);
    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm4Dec(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length,
                                               jbyteArray key_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);

    sms4_key_t sms4DecKey;
    sms4_set_decrypt_key(&sms4DecKey, (const unsigned char *) key);

    unsigned char *out = (unsigned char *) malloc(length);
    memset(out, 0, length);

    for (int i = 0; i < length / 16; i++) {
        sms4_decrypt((const unsigned char *) (in + (i * 16)), out + i * 16, &sms4DecKey);
    }
    //去补位
    int padinglen = out[length - 1];
    memset(out + length - padinglen, 0, padinglen);

    jbyteArray array = env->NewByteArray(length - padinglen);
    env->SetByteArrayRegion(array, 0, length - padinglen, (const jbyte *) out);

    free(out);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm2Enc(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);

    int iRet = 0;
    EC_KEY *ec_key = getEcKey();
    size_t sm2EncLen = SM2_MAX_PLAINTEXT_LENGTH;

    unsigned char *sm2EncMsg = (unsigned char *) malloc(SM2_MAX_PLAINTEXT_LENGTH);
    memset(sm2EncMsg, 0, SM2_MAX_PLAINTEXT_LENGTH);

    iRet = SM2_encrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       sm2EncMsg,
                       &sm2EncLen,
                       ec_key);

    if (!iRet) {
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();

        unsigned long ulErr = ERR_get_error(); // 获取错误号

        const char *pTmp = ERR_reason_error_string(ulErr);
        puts(pTmp);
    }

    jbyteArray array = env->NewByteArray(sm2EncLen);
    env->SetByteArrayRegion(array, 0, sm2EncLen, (const jbyte *) sm2EncMsg);

    free(sm2EncMsg);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);

    return array;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm2Dec(JNIEnv *env,
                                               jobject instance,
                                               jbyteArray in_,
                                               jint length) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);

    int iRet = 0;
    EC_KEY *ec_key = getEcKey();
    size_t sm2DecLen = 0;

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       NULL,
                       &sm2DecLen,
                       ec_key);

    unsigned char *sm2DecMsg = (unsigned char *) malloc(sm2DecLen + 1);
    memset(sm2DecMsg, 0, sm2DecLen);

    iRet = SM2_decrypt(NID_sm3,
                       (const unsigned char *) in,
                       (size_t) length,
                       sm2DecMsg,
                       &sm2DecLen,
                       ec_key);

    jbyteArray array = env->NewByteArray(sm2DecLen);
    env->SetByteArrayRegion(array, 0, sm2DecLen, (const jbyte *) sm2DecMsg);

    free(sm2DecMsg);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);

    return array;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_sm2Sign(JNIEnv *env,
                                                jobject instance,
                                                jbyteArray in_,
                                                jint length) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    int iret = -1;

    EC_KEY *ec_key = getEcKey();


    size_t zlen = 0;
    iret = SM2_compute_message_digest(EVP_sm3(),
                                      EVP_sm3(),
                                      (const unsigned char *) in,
                                      length,
                                      SM2_DEFAULT_ID_GMT09,
                                      SM2_DEFAULT_ID_LENGTH,
                                      NULL,
                                      &zlen,
                                      ec_key);
    if (!iret) {
        return NULL;
    }
    unsigned char *z = (unsigned char *) malloc(zlen + 1);
    memset(z, 0, zlen + 1);
    iret = SM2_compute_message_digest(EVP_sm3(),
                                      EVP_sm3(),
                                      (const unsigned char *) in,
                                      length,
                                      SM2_DEFAULT_ID_GMT09,
                                      SM2_DEFAULT_ID_LENGTH,
                                      z,
                                      &zlen,
                                      ec_key);
    if (!iret) {
        return NULL;
    }

    unsigned int signLen = 0;
    iret = SM2_sign(NID_sm3, z, zlen, NULL, &signLen, ec_key);
    if (!iret) {
        return NULL;
    }
    unsigned char *signMsg = (unsigned char *) malloc(signLen + 1);
    memset(signMsg, 0, signLen + 1);
    iret = SM2_sign(NID_sm3, z, zlen, signMsg, &signLen, ec_key);
    if (!iret) {
        return NULL;
    }

    jbyteArray array = env->NewByteArray(signLen);
    env->SetByteArrayRegion(array, 0, signLen, (const jbyte *) signMsg);

    free(signMsg);
    free(z);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);
    return array;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_gmssldemo_MainActivity_sm2Verify(JNIEnv *env,
                                                  jobject instance,
                                                  jbyteArray in_,
                                                  jint length,
                                                  jbyteArray sign_,
                                                  jint signLen) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *sign = env->GetByteArrayElements(sign_, NULL);
    int iret = -1;
    EC_KEY *ec_key = getEcKey();

    size_t zlen = 0;
    iret = SM2_compute_message_digest(EVP_sm3(),
                                      EVP_sm3(),
                                      (const unsigned char *) in,
                                      length,
                                      SM2_DEFAULT_ID_GMT09,
                                      SM2_DEFAULT_ID_LENGTH,
                                      NULL,
                                      &zlen,
                                      ec_key);

    unsigned char *z = (unsigned char *) malloc(zlen + 1);
    memset(z, 0, zlen + 1);
    iret = SM2_compute_message_digest(EVP_sm3(),
                                      EVP_sm3(),
                                      (const unsigned char *) in,
                                      length,
                                      SM2_DEFAULT_ID_GMT09,
                                      SM2_DEFAULT_ID_LENGTH,
                                      z,
                                      &zlen,
                                      ec_key);
    if (!iret) {
        return -2;
    }

    iret = SM2_verify(NID_sm3, z, zlen, (const unsigned char *) sign, signLen, ec_key);

    free(z);
    EC_KEY_free(ec_key);
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(sign_, sign, 0);
    return iret;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_rsaEnc(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, cipherText_offset = 0, desText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
//    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    desText_len = flen * (src_Len / (flen - 11) + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *cipherText = (unsigned char *) malloc(flen);
    unsigned char *desText = (unsigned char *) malloc(desText_len);
    memset(desText, 0, desText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGI("RSA->进行公钥加密操作");
    //RSA_PKCS1_PADDING最大加密长度：128-11；RSA_NO_PADDING最大加密长度：128
    for (int i = 0; i <= src_Len / (flen - 11); i++) {
        src_flen = (i == src_Len / (flen - 11)) ? src_Len % (flen - 11) : flen - 11;
        if (src_flen == 0) {
            break;
        }

        memset(cipherText, 0, flen);
        ret = RSA_public_encrypt(src_flen, srcOrigin + src_offset, cipherText, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + cipherText_offset, cipherText, ret);
        cipherText_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(cipherText_offset);
//    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, cipherText_offset, (jbyte *) desText);
//    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(cipherText);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_rsaDes(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    int ret = 0, src_flen = 0, plaintext_offset = 0, descText_len = 0, src_offset = 0;

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGI("RSA->从字符串读取RSA私钥");
    keybio = BIO_new_mem_buf(keys, -1);
//    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    int flen = RSA_size(rsa);
    descText_len = (flen - 11) * (src_Len / flen + 1);

    unsigned char *srcOrigin = (unsigned char *) malloc(src_Len);
    unsigned char *plaintext = (unsigned char *) malloc(flen - 11);
    unsigned char *desText = (unsigned char *) malloc(descText_len);
    memset(desText, 0, descText_len);

    memset(srcOrigin, 0, src_Len);
    memcpy(srcOrigin, src, src_Len);

//    LOGI("RSA->进行私钥解密操作");
    //一次性解密数据最大字节数RSA_size
    for (int i = 0; i <= src_Len / flen; i++) {
        src_flen = (i == src_Len / flen) ? src_Len % flen : flen;
        if (src_flen == 0) {
            break;
        }

        memset(plaintext, 0, flen - 11);
        ret = RSA_private_decrypt(src_flen, srcOrigin + src_offset, plaintext, rsa, RSA_PKCS1_PADDING);

        memcpy(desText + plaintext_offset, plaintext, ret);
        plaintext_offset += ret;
        src_offset += src_flen;
    }

    RSA_free(rsa);
//    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(plaintext_offset);
//    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, plaintext_offset, (jbyte *) desText);
//    LOGI("RSA->释放内存");
    free(srcOrigin);
    free(plaintext);
    free(desText);

    return cipher;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_gmssldemo_MainActivity_rsaSign(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_) {
//    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jsize src_Len = env->GetArrayLength(src_);

    unsigned int siglen = 0;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
//    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
//    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    unsigned char *sign = (unsigned char *) malloc(129);
    memset(sign, 0, 129);

    SHA1((const unsigned char *) src, src_Len, digest);
    RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sign, &siglen, rsa);

    RSA_free(rsa);
//    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);

    jbyteArray cipher = env->NewByteArray(siglen);
//    LOGI("RSA->在堆中分配ByteArray数组对象成功，将拷贝数据到数组中");
    env->SetByteArrayRegion(cipher, 0, siglen, (jbyte *) sign);
//    LOGI("RSA->释放内存");
    free(sign);

    return cipher;
}


extern "C" JNIEXPORT jint JNICALL
Java_com_example_gmssldemo_MainActivity_rsaVerify(JNIEnv *env, jobject instance, jbyteArray keys_, jbyteArray src_, jbyteArray sign_) {
//    LOGI("RSA->非对称密码算法，也就是说该算法需要一对密钥，使用其中一个加密，则需要用另一个才能解密");
    jbyte *keys = env->GetByteArrayElements(keys_, NULL);
    jbyte *src = env->GetByteArrayElements(src_, NULL);
    jbyte *sign = env->GetByteArrayElements(sign_, NULL);

    jsize src_Len = env->GetArrayLength(src_);
    jsize siglen = env->GetArrayLength(sign_);

    int ret;
    unsigned char digest[SHA_DIGEST_LENGTH];

    RSA *rsa = NULL;
    BIO *keybio = NULL;

//    LOGI("RSA->从字符串读取RSA公钥");
    keybio = BIO_new_mem_buf(keys, -1);
//    LOGI("RSA->从bio结构中得到RSA结构");
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, NULL, NULL, NULL);
//    LOGI("RSA->释放BIO");
    BIO_free_all(keybio);

    SHA1((const unsigned char *) src, src_Len, digest);
    ret = RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, (const unsigned char *) sign, siglen, rsa);

    RSA_free(rsa);
//    LOGI("RSA->CRYPTO_cleanup_all_ex_data");
    CRYPTO_cleanup_all_ex_data();

//    LOGI("RSA->从jni释放数据指针");
    env->ReleaseByteArrayElements(keys_, keys, 0);
    env->ReleaseByteArrayElements(src_, src, 0);
    env->ReleaseByteArrayElements(sign_, sign, 0);

    return ret;
}

