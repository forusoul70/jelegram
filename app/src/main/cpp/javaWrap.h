//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_JAVAWRAP_H
#define JELEGRAM_JAVAWRAP_H

#include <jni.h>
#include <stdlib.h>
#include "logging.h"

static JavaVM *javaVm;
static jclass JavaByteBuffer;
static jmethodID JavaByteBufferAllocateDirect;

extern "C" inline void initialize(JavaVM* vm) {
    javaVm = vm;

    JNIEnv *env = 0;
    if (javaVm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        LOGE("JavaWrap", "can't get jni env");
        exit(1);
    }
    JavaByteBuffer = (jclass) env->NewGlobalRef(env->FindClass("java/nio/ByteBuffer"));
    if (JavaByteBuffer == 0) {
        LOGE("JavaWrap", "can't find java buffer class");
        exit(1);
    }

    JavaByteBufferAllocateDirect = env->GetStaticMethodID(JavaByteBuffer, "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
    if (JavaByteBufferAllocateDirect == 0) {
        LOGE("JavaWrap", "can't find ByteBuffer allocateDirect");
        exit(1);
    }
}

#endif //JELEGRAM_JAVAWRAP_H
