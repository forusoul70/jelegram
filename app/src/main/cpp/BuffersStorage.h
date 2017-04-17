//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_BUFFERSSTORAGE_H
#define JELEGRAM_BUFFERSSTORAGE_H

#include <vector>
#include <pthread.h>
#include <stdint.h>

class NativeByteBuffer;

class BuffersStorage {

public:
    BuffersStorage(bool threadSafe);
    NativeByteBuffer *getFreeBuffer(uint32_t size);
    void reuseFreeBuffer(NativeByteBuffer *buffer);
    static BuffersStorage &getInstance();

private:
    std::vector<NativeByteBuffer *> freeBuffers8;
    std::vector<NativeByteBuffer *> freeBuffers128;
    std::vector<NativeByteBuffer *> freeBuffers1024;
    std::vector<NativeByteBuffer *> freeBuffers4096;
    std::vector<NativeByteBuffer *> freeBuffers16384;
    std::vector<NativeByteBuffer *> freeBuffers32768;
    std::vector<NativeByteBuffer *> freeBuffersBig;
    bool isThreadSafe = true;
    pthread_mutex_t mutex;
};


#endif //JELEGRAM_BUFFERSSTORAGE_H
