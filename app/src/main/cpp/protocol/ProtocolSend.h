//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_REQUEST_H
#define JELEGRAM_REQUEST_H

#include <memory>
#include "../NativeByteBuffer.h"

class NativeByteBuffer;
class ProtocolSend {
public:
    ProtocolSend(NativeByteBuffer *buffer); // auto delete
    virtual ~ProtocolSend();

    NativeByteBuffer* getBuffer();

private:
    NativeByteBuffer* mRequestData;
};
typedef std::shared_ptr<ProtocolSend> ProtocolSendPtr;

#endif //JELEGRAM_REQUEST_H
