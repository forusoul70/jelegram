#include <stdlib.h>
#include "logging.h"
#include "connections/ConnectionManager.h"
#include "javaWrap.h"
#include "openssl/aes.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"

#define LOG_TAG "native-lib"

inline uint64_t gcd(uint64_t a, uint64_t b);
inline bool factorizeValue(uint64_t what, uint32_t &p, uint32_t &q);

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
Java_jelegram_forusoul_com_cipher_CipherManager_native_1requestAesCtrEncrypt(JNIEnv *env,
                                                                             jclass type,
                                                                             jbyteArray in_,
                                                                             jbyteArray out_,
                                                                             jint length,
                                                                             jbyteArray encryptionKey_,
                                                                             jbyteArray initializeVector_,
                                                                             jbyteArray counterBuffer_,
                                                                             jintArray number_) {
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

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("native-lib", "JNI_OnLoad");
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

#undef LOG_TAG