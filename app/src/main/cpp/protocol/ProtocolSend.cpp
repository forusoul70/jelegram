//
// Created by lee on 17. 4. 17.
//

#include "ProtocolSend.h"

ProtocolSend::ProtocolSend(NativeByteBuffer *buffer):
mRequestData(nullptr) {
    mRequestData = buffer;
}

ProtocolSend::~ProtocolSend() {
    delete mRequestData;
}

NativeByteBuffer *ProtocolSend::getBuffer() {
    return mRequestData;
}

