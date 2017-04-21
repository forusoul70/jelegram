//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_LOG_H
#define JELEGRAM_LOG_H

#include <android/log.h>
#include <string>
#include <stdio.h>
#include "NativeByteBuffer.h"

#define  LOGI(LOG_TAG,...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG, __VA_ARGS__)
#define  LOGD(LOG_TAG,...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, __VA_ARGS__)
#define  LOGW(LOG_TAG,...)  __android_log_print(ANDROID_LOG_WARN,LOG_TAG, __VA_ARGS__)
#define  LOGE(LOG_TAG,...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG, __VA_ARGS__)

extern "C" inline void printByteBuffer(NativeByteBuffer *buffer) {
    if (buffer == nullptr) {
        return;
    }

    // Debug
    std::string outPutString("");
    int index = 0;
    char debugBuffer[5];

    size_t size = buffer->limit();
    uint8_t *bytes = buffer->bytes();
    while (index < size) {
        for (int i=0; i < 8; i++) {
            if (index >= size) {
                break;
            }

            snprintf(debugBuffer, 5, "0x%02x", *(bytes + index));
            outPutString += debugBuffer;
            outPutString += ", ";
            index++;
        }
        outPutString +="\n";
    }
    LOGD("LOGGGING", "%s [%d]", outPutString.c_str(), size);
}

#endif //JELEGRAM_LOG_H
