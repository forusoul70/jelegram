#include <stdlib.h>
#include <memory>
#include <openssl/rand.h>
#include "logging.h"
#include "connections/ConnectionManager.h"
#include "javaWrap.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"

#define LOG_TAG "native-lib"

inline uint64_t gcd(uint64_t a, uint64_t b);
inline bool factorizeValue(uint64_t what, uint32_t &p, uint32_t &q);
inline bool isGoodPrime(BIGNUM *p, uint32_t g);
inline bool isGoodGaAndGb(BIGNUM *g_a, BIGNUM *p);
inline bool check_prime(BIGNUM *p);

static BN_CTX *bnContext;

// Network manager listener
class NetworkManagerDelegate : public ConnectionManagerListener {
public:
    NetworkManagerDelegate():
        mJavaConnectionManagerClass(NULL)
        ,mByteReceivedMethod(NULL) {
        JNIEnv *env = 0;
        if (javaVm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
            LOGE("native-lib", "NetworkManagerDelegate(), can't get jni env");
            exit(1);
        }
        mJavaConnectionManagerClass = (jclass) env->NewGlobalRef(env->FindClass("jelegram/forusoul/com/connection/ConnectionManager"));
        mByteReceivedMethod = env->GetStaticMethodID(mJavaConnectionManagerClass, "onByteReceived", "([B)V");
    }

    virtual void onByteReceived(NativeByteBufferPtr buffer) {
        JNIEnv *env = nullptr;
        if (javaVm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
            javaVm->AttachCurrentThread(&env, NULL);
            if (env == nullptr) {
                LOGE("Jnative-lib", "onByteReceived(), can't get jni env");
                exit(1);
            }
        }
        jbyteArray javaBuffer = env->NewByteArray(buffer->limit());
        if (javaBuffer == nullptr) {
            LOGE("ConnectionManagerListener", "Failed to allocate java buffer [%d]",buffer->limit());
            return;
        }

        env->SetByteArrayRegion(javaBuffer, 0, buffer->limit(), reinterpret_cast<jbyte*>(buffer->bytes()));
        env->CallStaticVoidMethod(mJavaConnectionManagerClass, mByteReceivedMethod, javaBuffer);
    }

private:
    jclass mJavaConnectionManagerClass;
    jmethodID mByteReceivedMethod;
};

extern "C"
JNIEXPORT void JNICALL
Java_jelegram_forusoul_com_connection_ConnectionManager_native_1send_1request(JNIEnv *env,
                                                                              jclass type,
                                                                              jbyteArray request_) {
    jbyte *request = env->GetByteArrayElements(request_, NULL);
    int length = env->GetArrayLength(request_);

    NativeByteBuffer* requestBuffer = new NativeByteBuffer((uint8_t *) request, length);
    ConnectionManager::getInstance().sendRequest(std::make_shared<ProtocolSend>(requestBuffer));

    // Do not release JVM memory. Buffer is going to be released on destructor of Request..
    // 근데 진짜 안해도 되나???
//    env->ReleaseByteArrayElements(request_, request, 0);
}

extern "C"
JNIEXPORT void JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestAesCtrEncrypt(JNIEnv *env, jclass type, jbyteArray in_, jbyteArray out_, jint length, jbyteArray encryptionKey_,
                                                                             jbyteArray initializeVector_, jbyteArray counterBuffer_, jintArray number_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *out = env->GetByteArrayElements(out_, NULL);
    jbyte *encryptionKey = env->GetByteArrayElements(encryptionKey_, NULL);
    jbyte *initializeVector = env->GetByteArrayElements(initializeVector_, NULL);
    jbyte *counterBuffer = env->GetByteArrayElements(counterBuffer_, NULL);
    jint *number = env->GetIntArrayElements(number_, NULL);

    AES_KEY key;
    int result = AES_set_encrypt_key((const uint8_t *) encryptionKey, 256, &key);
    if (result >= 0) {
        AES_ctr128_encrypt((const uint8_t *) in, (uint8_t *) out, (size_t) length, &key,
                           (uint8_t *) initializeVector, (uint8_t *) counterBuffer,
                           (unsigned int *) number);
    }

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(out_, out, 0);
    env->ReleaseByteArrayElements(encryptionKey_, encryptionKey, 0);
    env->ReleaseByteArrayElements(initializeVector_, initializeVector, 0);
    env->ReleaseByteArrayElements(counterBuffer_, counterBuffer, 0);
    env->ReleaseIntArrayElements(number_, number, 0);
};


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestRsaEncrypt(JNIEnv *env, jclass type,
                                                                          jstring publicKey_,
                                                                          jbyteArray in_) {
    const char *publicKey = env->GetStringUTFChars(publicKey_, 0);
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    int inputLength = env->GetArrayLength(in_);

    BIO *keyBio = BIO_new((const BIO_METHOD *) BIO_s_mem());
    BIO_write(keyBio, publicKey, strlen(publicKey));

    RSA *rsaKey = PEM_read_bio_RSAPublicKey(keyBio, NULL, NULL, NULL);
    BN_CTX *bnContext = BN_CTX_new();

    BIGNUM *a = BN_bin2bn((const uint8_t *) in, (size_t) inputLength, NULL);
    BIGNUM *r = BN_new();
    BN_mod_exp(r, a, rsaKey->e, rsaKey->n, bnContext);
    uint32_t size = BN_num_bytes(r);
    uint8_t *encryptionBytes = new uint8_t[size];
    size_t resLen = BN_bn2bin(r, encryptionBytes);

    BIO_free(keyBio);
    BN_free(a);
    BN_free(r);
    RSA_free(rsaKey);
    BN_CTX_free(bnContext);

    if (resLen < 0) {
        LOGE(LOG_TAG, "Failed to encryption rsa");
        return nullptr;
    }

    jbyteArray convertedEncryption = env->NewByteArray(resLen);
    if (convertedEncryption == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [%d]", resLen);
        return nullptr;
    }

    env->SetByteArrayRegion(convertedEncryption, 0, resLen, reinterpret_cast<jbyte*>(encryptionBytes));
    env->ReleaseStringUTFChars(publicKey_, publicKey);
    env->ReleaseByteArrayElements(in_, in, 0);

    delete[] encryptionBytes;

    return convertedEncryption;
}

extern "C"
JNIEXPORT jintArray JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestFactorizePQ(JNIEnv *env, jclass type, jbyteArray pqValue_) {
    jbyte *pqValue = env->GetByteArrayElements(pqValue_, NULL);
    int length = env->GetArrayLength(pqValue_);
    if (length != 8) {
        LOGE(LOG_TAG, "Invalid pq value length");
        return nullptr;
    }
    
    uint8_t *pqByte = (uint8_t*) pqValue;
    uint64_t pq = ((uint64_t) (pqByte[0] & 0xff) << 56) |
                  ((uint64_t) (pqByte[1] & 0xff) << 48) |
                  ((uint64_t) (pqByte[2] & 0xff) << 40) |
                  ((uint64_t) (pqByte[3] & 0xff) << 32) |
                  ((uint64_t) (pqByte[4] & 0xff) << 24) |
                  ((uint64_t) (pqByte[5] & 0xff) << 16) |
                  ((uint64_t) (pqByte[6] & 0xff) << 8) |
                  ((uint64_t) (pqByte[7] & 0xff));

    uint32_t pqNativeArray[2];
    memset(pqNativeArray, 0, sizeof(uint32_t) * 2);

    if (factorizeValue(pq, pqNativeArray[0], pqNativeArray[1]) == false) {
        LOGE(LOG_TAG, "Failed to factorize");
        return nullptr;
    }

    jintArray pqArray = env->NewIntArray(2);
    if (pqArray == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java int buffer [2]");
        return nullptr;
    }

    env->SetIntArrayRegion(pqArray, 0, 2, reinterpret_cast<jint*>(pqNativeArray));
    env->ReleaseByteArrayElements(pqValue_, pqValue, 0);

    return pqArray;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestDecryptAesIge(JNIEnv *env, jclass type, jbyteArray in_, jbyteArray key_, jbyteArray iv_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);
    jbyte *iv = env->GetByteArrayElements(iv_, NULL);
    int inputLength = env->GetArrayLength(in_);
    int ivLength = env->GetArrayLength(iv_);

    if (in == nullptr || inputLength == 0) {
        LOGE(LOG_TAG, "Input buffer is empty");
        return nullptr;
    }

    if (iv == nullptr || ivLength != 32) {
        LOGE(LOG_TAG, "Invalid initialize vector length [%d]", ivLength);
        return nullptr;
    }

    uint8_t *cloneIv = new uint8_t[32];
    memcpy(cloneIv, iv, (size_t) ivLength);

    // make out buffer
    uint8_t *out = new uint8_t[inputLength];
    memcpy(out, in, (size_t) inputLength);

    // aes ige mode
    AES_KEY aesKey;
    AES_set_decrypt_key((const uint8_t *) key, 32 * 8, &aesKey);
    AES_ige_encrypt((const uint8_t*)in, out, (size_t) inputLength, &aesKey, cloneIv, AES_DECRYPT);

    jbyteArray decryptedData = env->NewByteArray(inputLength);
    if (decryptedData == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [%d]", inputLength);
        return nullptr;
    }
    env->SetByteArrayRegion(decryptedData, 0, inputLength, reinterpret_cast<jbyte*>(out));

    // release
    delete[] out;
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);
    env->ReleaseByteArrayElements(iv_, iv, 0);

    return decryptedData;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestEncryptAesIge(JNIEnv *env, jclass type, jbyteArray in_, jbyteArray key_, jbyteArray iv_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *key = env->GetByteArrayElements(key_, NULL);
    jbyte *iv = env->GetByteArrayElements(iv_, NULL);
    int inputLength = env->GetArrayLength(in_);
    int ivLength = env->GetArrayLength(iv_);

    if (in == nullptr || inputLength == 0) {
        LOGE(LOG_TAG, "Input buffer is empty");
        return nullptr;
    }

    if (iv == nullptr || ivLength != 32) {
        LOGE(LOG_TAG, "Invalid initialize vector length [%d]", ivLength);
        return nullptr;
    }

    uint8_t *cloneIv = new uint8_t[32];
    memcpy(cloneIv, iv, (size_t) ivLength);

    // make out buffer
    uint8_t *out = new uint8_t[inputLength];
    memcpy(out, in, (size_t) inputLength);

    // aes ige mode
    AES_KEY aesKey;
    AES_set_encrypt_key((const uint8_t *) key, 32 * 8, &aesKey);
    AES_ige_encrypt((const uint8_t*)in, out, (size_t) inputLength, &aesKey, cloneIv, AES_ENCRYPT);

    jbyteArray decryptedData = env->NewByteArray(inputLength);
    if (decryptedData == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [%d]", inputLength);
        return nullptr;
    }
    env->SetByteArrayRegion(decryptedData, 0, inputLength, reinterpret_cast<jbyte*>(out));

    // release
    delete[] out;
    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(key_, key, 0);
    env->ReleaseByteArrayElements(iv_, iv, 0);

    return decryptedData;
}

extern "C"
JNIEXPORT void JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestCalculateDiffieHellmanGB(JNIEnv *env, jclass type, jbyteArray prime_, jint g,
                                                                                        jbyteArray ga_, jobject callback) {
    // callback
    jclass callbackInterface = env->GetObjectClass(callback);
    jmethodID callbackMethod = env->GetMethodID(callbackInterface, "onFinished", "([B[B)V");

    uint8_t *primeBytes = (uint8_t *) env->GetByteArrayElements(prime_, NULL);
    uint8_t *gaBytes = (uint8_t *) env->GetByteArrayElements(ga_, NULL);
    size_t primeLength = (size_t) env->GetArrayLength(prime_);
    size_t gaLength = (size_t) env->GetArrayLength(ga_);

    if (primeBytes == nullptr || primeLength == 0) {
        LOGE(LOG_TAG, "Input prime is empty");
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    BIGNUM *bigP = BN_bin2bn(primeBytes, primeLength, NULL);
    if (bigP == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate Big number");
        BN_free(bigP);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    if (isGoodPrime(bigP, (uint32_t) g) == false) {
        LOGE(LOG_TAG, "Is not good prime");
        BN_free(bigP);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    BIGNUM *bigGA = BN_new();
    if (bigGA == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number [ga]");
        BN_free(bigP);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    BN_bin2bn(gaBytes, gaLength, bigGA);
    if (isGoodGaAndGb(bigGA, bigP) == false) {
        LOGE(LOG_TAG, "Bad prime and g_a");
        BN_free(bigP);
        BN_free(bigGA);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    BIGNUM *bigG = BN_new();
    if (bigG == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number [g]");
        BN_free(bigP);
        BN_free(bigGA);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    if (BN_set_word(bigG, (uint32_t) g) == false) {
        LOGE(LOG_TAG, "failed to call BN_set_word()");
        BN_free(bigP);
        BN_free(bigGA);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    uint8_t byteB[256];
    RAND_bytes(byteB, 256);
    BIGNUM *bigB = BN_bin2bn(byteB, 256, NULL);
    if (bigB == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number [b]");
        BN_free(bigP);
        BN_free(bigGA);
        BN_free(bigG);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    BIGNUM *bigGB = BN_new();
    if (BN_mod_exp(bigGB, bigG, bigB, bigP, bnContext) == false) {
        LOGE(LOG_TAG, "Failed to call BN_mode_exp");
        BN_free(bigP);
        BN_free(bigGA);
        BN_free(bigG);
        BN_free(bigGB);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    size_t gbLength = BN_num_bytes(bigGB);
    uint8_t *gbBytes = new uint8_t[gbLength];
    BN_bn2bin(bigGB, gaBytes);

    jbyteArray outB = env->NewByteArray(256);
    if (outB == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [256]");
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    jbyteArray outGB = env->NewByteArray(gbLength);
    if (outGB == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [%d]", gbLength);
        env->CallVoidMethod(callback, callbackMethod, nullptr, nullptr);
        return;
    }

    // set result
    env->SetByteArrayRegion(outB, 0, 256, reinterpret_cast<jbyte*>(byteB));
    env->SetByteArrayRegion(outGB, 0, gbLength, reinterpret_cast<jbyte*>(gbBytes));

    // release
    env->ReleaseByteArrayElements(prime_, (jbyte *) primeBytes, 0);
    env->ReleaseByteArrayElements(ga_, (jbyte *) gaBytes, 0);

    delete[] gaBytes;
    BN_free(bigP);
    BN_free(bigGA);
    BN_free(bigG);
    BN_free(bigGB);

    env->CallVoidMethod(callback, callbackMethod, outB, outGB);
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestCalculateModExp(JNIEnv *env, jclass type, jbyteArray in_, jbyteArray prime_, jbyteArray mod_) {
    jbyte *in = env->GetByteArrayElements(in_, NULL);
    jbyte *prime = env->GetByteArrayElements(prime_, NULL);
    jbyte *mod = env->GetByteArrayElements(mod_, NULL);
    size_t aLength = (size_t) env->GetArrayLength(in_);
    size_t primeLength = (size_t) env->GetArrayLength(prime_);
    size_t modLength = (size_t) env->GetArrayLength(mod_);

    BIGNUM *a = BN_bin2bn((const uint8_t *) in, aLength, NULL);
    if (a == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number");
        return nullptr;
    }

    BIGNUM *p = BN_bin2bn((const uint8_t *) prime, primeLength, NULL);
    if (p == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number");
        return nullptr;
    }
    BIGNUM *m = BN_bin2bn((const uint8_t *) mod, modLength, NULL);
    if (m == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate big number");
        return nullptr;
    }

    BIGNUM *r = BN_new();
    BN_mod_exp(r, a, p, m, bnContext);
    size_t rLength = BN_num_bytes(r);
    uint8_t *rBuffer = new uint8_t(rLength);

    jbyteArray rJava = env->NewByteArray(rLength);
    if (rJava == nullptr) {
        LOGE(LOG_TAG, "Failed to allocate java buffer [%d]", rLength);
        return nullptr;
    }
    env->SetByteArrayRegion(rJava, 0, rLength, reinterpret_cast<jbyte*>(rBuffer));

    env->ReleaseByteArrayElements(in_, in, 0);
    env->ReleaseByteArrayElements(prime_, prime, 0);
    env->ReleaseByteArrayElements(mod_, mod, 0);

    delete[] rBuffer;

    return rJava;
}


int JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("native-lib", "JNI_OnLoad");
    bnContext = BN_CTX_new();
    initialize(vm);
    ConnectionManager::getInstance().setListener(new NetworkManagerDelegate());
    return JNI_VERSION_1_6;
}

bool factorizeValue(uint64_t what, uint32_t &p, uint32_t &q) {
    int32_t it = 0, i, j;
    uint64_t g = 0;
    for (i = 0; i < 3 || it < 1000; i++) {
        uint64_t t = ((lrand48() & 15) + 17) % what;
        uint64_t x = (long long) lrand48() % (what - 1) + 1, y = x;
        int32_t lim = 1 << (i + 18);
        for (j = 1; j < lim; j++) {
            ++it;
            uint64_t a = x, b = x, c = t;
            while (b) {
                if (b & 1) {
                    c += a;
                    if (c >= what) {
                        c -= what;
                    }
                }
                a += a;
                if (a >= what) {
                    a -= what;
                }
                b >>= 1;
            }
            x = c;
            uint64_t z = x < y ? what + x - y : x - y;
            g = gcd(z, what);
            if (g != 1) {
                break;
            }
            if (!(j & (j - 1))) {
                y = x;
            }
        }
        if (g > 1 && g < what) {
            break;
        }
    }

    if (g > 1 && g < what) {
        p = (uint32_t) g;
        q = (uint32_t) (what / g);
        if (p > q) {
            uint32_t tmp = p;
            p = q;
            q = tmp;
        }
        return true;
    } else {
        LOGE(LOG_TAG, "factorization failed for %llu", what);
        p = 0;
        q = 0;
        return false;
    }
}

uint64_t gcd(uint64_t a, uint64_t b) {
    while (a != 0 && b != 0) {
        while ((b & 1) == 0) {
            b >>= 1;
        }
        while ((a & 1) == 0) {
            a >>= 1;
        }
        if (a > b) {
            a -= b;
        } else {
            b -= a;
        }
    }
    return b == 0 ? a : b;
}

bool isGoodPrime(BIGNUM *p, uint32_t g) {
    //TODO check against known good primes
    if (g < 2 || g > 7 || BN_num_bits(p) != 2048) {
        return false;
    }

    BIGNUM *t = BN_new();
    BIGNUM *dh_g = BN_new();

    if (!BN_set_word(dh_g, 4 * g)) {
        LOGE(LOG_TAG, "OpenSSL error at BN_set_word(dh_g, 4 * g)");
        BN_free(t);
        BN_free(dh_g);
        return false;
    }
    if (!BN_mod(t, p, dh_g, bnContext)) {
        LOGE(LOG_TAG, "OpenSSL error at BN_mod");
        BN_free(t);
        BN_free(dh_g);
        return false;
    }
    uint64_t x = BN_get_word(t);
    if (x >= 4 * g) {
        LOGE(LOG_TAG, "OpenSSL error at BN_get_word");
        BN_free(t);
        BN_free(dh_g);
        return false;
    }

    BN_free(dh_g);

    bool result = true;
    switch (g) {
        case 2:
            if (x != 7) {
                result = false;
            }
            break;
        case 3:
            if (x % 3 != 2) {
                result = false;
            }
            break;
        case 5:
            if (x % 5 != 1 && x % 5 != 4) {
                result = false;
            }
            break;
        case 6:
            if (x != 19 && x != 23) {
                result = false;
            }
            break;
        case 7:
            if (x % 7 != 3 && x % 7 != 5 && x % 7 != 6) {
                result = false;
            }
            break;
        default:
            break;
    }

    char *prime = BN_bn2hex(p);
    static const char *goodPrime = "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c3720fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f642477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b";
    if (!strcasecmp(prime, goodPrime)) {
        delete [] prime;
        BN_free(t);
        return true;
    }
    delete [] prime;

    if (!result || !check_prime(p)) {
        BN_free(t);
        return false;
    }

    BIGNUM *b = BN_new();
    if (!BN_set_word(b, 2)) {
        LOGE(LOG_TAG, "OpenSSL error at BN_set_word(b, 2)");
        BN_free(b);
        BN_free(t);
        return false;
    }
    if (!BN_div(t, 0, p, b, bnContext)) {
        LOGE(LOG_TAG, "OpenSSL error at BN_div");
        BN_free(b);
        BN_free(t);
        return false;
    }
    if (!check_prime(t)) {
        result = false;
    }
    BN_free(b);
    BN_free(t);
    return result;
}

bool isGoodGaAndGb(BIGNUM *g_a, BIGNUM *p) {
    if (BN_num_bytes(g_a) > 256 || BN_num_bits(g_a) < 2048 - 64 || BN_cmp(p, g_a) <= 0) {
        return false;
    }
    BIGNUM *dif = BN_new();
    BN_sub(dif, p, g_a);
    if (BN_num_bits(dif) < 2048 - 64) {
        BN_free(dif);
        return false;
    }
    BN_free(dif);
    return true;
}

bool check_prime(BIGNUM *p) {
    int result = 0;
    if (!BN_primality_test(&result, p, BN_prime_checks, bnContext, 0, NULL)) {
        LOGE(LOG_TAG, "OpenSSL error at BN_primality_test");
        return false;
    }
    return result != 0;
}

#undef LOG_TAG