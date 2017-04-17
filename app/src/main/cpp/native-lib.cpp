#include <stdlib.h>
#include "logging.h"
#include "connections/ConnectionManager.h"
#include "javaWrap.h"

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    initialize(vm);
    return JNI_VERSION_1_6;
};

extern "C"
JNIEXPORT void JNICALL Java_jelegram_forusoul_com_ConnectionManager_native_1send_1request(JNIEnv *env, jclass type, jbyteArray request_) {
    jbyte *request = env->GetByteArrayElements(request_, NULL);
    uint8_t length = (uint8_t) env->GetArrayLength(request_);

    NativeByteBuffer* requestBuffer = new NativeByteBuffer((uint8_t *) request, length);
    ConnectionManager::getInstance().sendRequest(std::make_shared<ProtocolSend>(requestBuffer));

    env->ReleaseByteArrayElements(request_, request, 0);
}

#undef LOG_TAG