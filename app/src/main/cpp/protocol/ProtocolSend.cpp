//
// Created by lee on 17. 4. 17.
//

#include "ProtocolSend.h"
#include "../logging.h"

#define LOG_TAG "ProtocolSend"

ProtocolSend::ProtocolSend(NativeByteBuffer *buffer):
mRequestData(nullptr) {
    mRequestData = buffer;
}

ProtocolSend::~ProtocolSend() {
    LOGD(LOG_TAG, "~ProtocolSend()");
    delete mRequestData;
}

NativeByteBuffer *ProtocolSend::getBuffer() {
    return mRequestData;
}

#undef LOG_TAG;

