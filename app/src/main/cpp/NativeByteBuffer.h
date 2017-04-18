//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_NATIVEBUFFER_H
#define JELEGRAM_NATIVEBUFFER_H


#include <stdint.h>
#include <string>

#ifdef ANDROID
#include <jni.h>
#include <memory>

#endif

class ByteArray;

class NativeByteBuffer {

public:
    NativeByteBuffer(uint32_t size);
    NativeByteBuffer(bool calculate);
    NativeByteBuffer(uint8_t *buff, uint32_t length);
    ~NativeByteBuffer();

    uint32_t position();
    void position(uint32_t position);
    uint32_t limit();
    void limit(uint32_t limit);
    uint32_t capacity();
    uint32_t remaining();
    bool hasRemaining();
    void rewind();
    void compact();
    void flip();
    void clear();
    void skip(uint32_t length);
    void clearCapacity();
    uint8_t *bytes();

    void writeInt32(int32_t x, bool *error);
    void writeInt64(int64_t x, bool *error);
    void writeBool(bool value, bool *error);
    void writeBytes(uint8_t *b, uint32_t length, bool *error);
    void writeBytes(uint8_t *b, uint32_t offset, uint32_t length, bool *error);
    void writeBytes(ByteArray *b, bool *error);
    void writeBytes(NativeByteBuffer *b, bool *error);
    void writeByte(uint8_t i, bool *error);
    void writeString(std::string s, bool *error);
    void writeByteArray(uint8_t *b, uint32_t offset, uint32_t length, bool *error);
    void writeByteArray(uint8_t *b, uint32_t length, bool *error);
    void writeByteArray(NativeByteBuffer *b, bool *error);
    void writeByteArray(ByteArray *b, bool *error);
    void writeDouble(double d, bool *error);
    void writeInt32(int32_t x);
    void writeInt64(int64_t x);
    void writeBool(bool value);
    void writeBytes(uint8_t *b, uint32_t length);
    void writeBytes(uint8_t *b, uint32_t offset, uint32_t length);
    void writeBytes(ByteArray *b);
    void writeBytes(NativeByteBuffer *b);
    void writeByte(uint8_t i);
    void writeString(std::string s);
    void writeByteArray(uint8_t *b, uint32_t offset, uint32_t length);
    void writeByteArray(uint8_t *b, uint32_t length);
    void writeByteArray(NativeByteBuffer *b);
    void writeByteArray(ByteArray *b);
    void writeDouble(double d);

    uint32_t readUint32(bool *error);
    uint64_t readUint64(bool *error);
    int32_t readInt32(bool *error);
    int32_t readBigInt32(bool *error);
    int64_t readInt64(bool *error);
    uint8_t readByte(bool *error);
    bool readBool(bool *error);
    void readBytes(uint8_t *b, uint32_t length, bool *error);
    ByteArray *readBytes(uint32_t length, bool *error);
    std::string readString(bool *error);
    ByteArray *readByteArray(bool *error);
    NativeByteBuffer *readByteBuffer(bool copy, bool *error);
    double readDouble(bool *error);

    void reuse();
    jobject getJavaByteBuffer();
private:
    void writeBytesInternal(uint8_t *b, uint32_t offset, uint32_t length);

    uint8_t *buffer = nullptr;
    bool calculateSizeOnly = false;
    bool sliced = false;
    uint32_t _position = 0;
    uint32_t _limit = 0;
    uint32_t _capacity = 0;
    bool bufferOwner = true;
    jobject javaByteBuffer = nullptr;
};
typedef std::shared_ptr<NativeByteBuffer> NativeByteBufferPtr;
#endif //JELEGRAM_NATIVEBUFFER_H
