#include <stdlib.h>
#include "logging.h"
#include "connections/ConnectionManager.h"
#include "javaWrap.h"
#include "openssl/aes.h"

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

        printByteBuffer(buffer.get());
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
    uint8_t length = (uint8_t) env->GetArrayLength(request_);

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

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("native-lib", "JNI_OnLoad");
    initialize(vm);
    ConnectionManager::getInstance().setListener(new NetworkManagerDelegate());
    return JNI_VERSION_1_6;
}
#undef LOG_TAG