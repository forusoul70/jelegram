//
// Created by lee on 17. 4. 17.
//

#ifndef JELEGRAM_CONNECTIONMANAGER_H
#define JELEGRAM_CONNECTIONMANAGER_H

#include <vector>
#include <pthread.h>
#include <sys/epoll.h>
#include <mutex>
#include "../protocol/ProtocolSend.h"
#include "../NativeByteBuffer.h"

typedef class ConnectionManagerListener {
public:
    virtual void onByteReceived(NativeByteBufferPtr buffer) = 0;
};

class ConnectionManager {
public:
    ~ConnectionManager();
    static ConnectionManager& getInstance();

    void sendRequest(ProtocolSendPtr request);

    void setListener(ConnectionManagerListener* listener);
private:
    enum ConnectionState {
        Idle,
        Connected,
        Connecting,
        Suspended
    };


    ConnectionManager();
    void initialize();
    static void* ThreadProc(void *data); // Connection thread loop

    void openConnection();
    void closeConnection();
    void selectOperation();

    void processPendingSendRequest();
    void processReceiveMessage();

    std::mutex mSendRequestTaskLock;
    std::vector<ProtocolSendPtr> mPendingSendRequestTask;
    pthread_t mNetworkThread;

    std::mutex mConnectionLock;
    ConnectionState mConnectionState;
    int mSocketFd;

    int mPollFd;
    int mPollEventFd;
    struct epoll_event *mPollEvents;

    NativeByteBufferPtr mReceiveBuffer;

    ConnectionManagerListener* mDelegate;
};
#endif //JELEGRAM_CONNECTIONMANAGER_H
