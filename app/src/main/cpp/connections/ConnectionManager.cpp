//
// Created by lee on 17. 4. 17.
//

#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <mutex>
#include "ConnectionManager.h"
#include "../logging.h"

#define LOG_TAG "ConnectionManager"

const int MAX_EVENT_COUNT = 128;

ConnectionManager::ConnectionManager()
:mConnectionState(Idle)
,mSocketFd(-1)
,mPollFd(-1)
,mPollEventFd(-1)
,mPollEvents(NULL) {
    // create epoll fd
    if ((mPollFd = epoll_create(MAX_EVENT_COUNT)) == -1) {
        LOGE(LOG_TAG, "Failed to create epoll instance");
        exit(1);
    }

    int flags;
    if ((flags = fcntl(mPollFd, F_GETFD, NULL)) < 0) {
        LOGW(LOG_TAG, "Failed, fcntl(%d, F_GETFD)", mPollFd);
    }

    if ((flags & FD_CLOEXEC) == false) {
        if (fcntl(mPollFd, F_SETFD, flags | FD_CLOEXEC) == -1) {
            LOGW(LOG_TAG, "Failed, fcntl(%d, F_SETFD)", mPollFd);
        }
    }

    if ((mPollEvents = new epoll_event[128]) == nullptr) {
        LOGE(LOG_TAG, "Unable to allocate epoll events");
        exit(1);
    }
    mPollEventFd = eventfd(0, EFD_NONBLOCK);
    if (mPollEventFd < 0) {
        LOGE(LOG_TAG, "Failed to create event fd");
        exit(1);
    }

    struct epoll_event event = {0};
    event.data.ptr = nullptr;
    event.events = EPOLLIN | EPOLLOUT;
    if (epoll_ctl(mPollFd, EPOLL_CTL_ADD, mPollEventFd, &event) < 0) {
        LOGE(LOG_TAG, "Failed to add poll event");
        exit(1);
    }
    // initialize
    initialize();
}

ConnectionManager& ConnectionManager::getInstance() {
    static ConnectionManager instance;
    return instance;
}

ConnectionManager::~ConnectionManager() {
    mPendingSendRequestTask.clear();
    if (mPollFd != -1) {
        close(mPollFd);
        mPollFd = 0;
    }

    delete[] mPollEvents;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
void* ConnectionManager::ThreadProc(void *data) {
    ConnectionManager *manager = (ConnectionManager*) (data);
    do {
        manager->selectOperation();
    } while (true);

    return nullptr;
}
#pragma clang diagnostic pop

void ConnectionManager::initialize() {
    pthread_create(&mNetworkThread, NULL, (ConnectionManager::ThreadProc), this);

    // connect socket
    openConnection();
}

void ConnectionManager::openConnection() {
    if (mPollEventFd < 0) {
        LOGE(LOG_TAG, "openConnection(), Current poll event fd invalid");
        return;
    }

    std::lock_guard<std::mutex> lock(mConnectionLock);
    mConnectionState = Suspended;
    if ((mSocketFd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOGE(LOG_TAG, "Failed to open socket");
        closeConnection();
        return;
    }

    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    struct addrinfo *server = nullptr;
    if (getaddrinfo("149.154.175.50", "443", &hint, &server) != 0) {
        LOGE(LOG_TAG, "Failed to find server address");
        exit(1);
    }

    for (addrinfo* p = server; p != nullptr; p = p->ai_next) {
        if ((mSocketFd = socket(p->ai_family, p->ai_socktype, 0)) < 0) {
            LOGE(LOG_TAG, "Failed to create socket");
            continue;
        }

        if (connect(mSocketFd, p->ai_addr, p->ai_addrlen) < 0) {
            LOGE(LOG_TAG, "Failed to connect");
            continue;
        }
        break;
    }

    freeaddrinfo(server);

    struct epoll_event event = {0};
    event.data.ptr = nullptr;
    event.events = EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLET;
    if (epoll_ctl(mPollFd, EPOLL_CTL_ADD, mSocketFd, &event) != 0) {
        LOGE(LOG_TAG, "openConnection() epoll_ctl, adding socket failed", this);
        closeConnection();
        return;
    }
    mConnectionState = Connected;
}


void ConnectionManager::closeConnection() {
    std::lock_guard<std::mutex> lock(mConnectionLock);
    if (mSocketFd >= 0) {
        close(mSocketFd);
    }
    mConnectionState = Suspended;
}

void ConnectionManager::selectOperation() {
    int eventCount = epoll_wait(mPollFd, mPollEvents, MAX_EVENT_COUNT, 100);
    if (eventCount < 0) {
        LOGD(LOG_TAG, "selectOperation(), Failed to wait error : [%d] pollFd : [%d]", mPollFd, errno);
        exit(1);
    }

    std::lock_guard<std::mutex> lock(mConnectionLock);
    for (int32_t i = 0; i < eventCount; i++) {
        switch (mPollEvents[i].events) {
            case EPOLLIN:
                LOGD(LOG_TAG, "selectOperation(), EPOLLIN");
                break;
            case EPOLLOUT:
                LOGD(LOG_TAG, "selectOperation(), EPOLLOUT");
                processPendingSendRequest();
                break;
            default:
                break;
        }
    }
}

void ConnectionManager::sendRequest(ProtocolSendPtr request) {
    if (request == nullptr) {
        return;
    }

    if (mPollEventFd < 0) {
        LOGE(LOG_TAG, "sendRequest(), Current poll event fd is empty");
        return;
    }

    std::lock_guard<std::mutex> lock(mSendRequestTaskLock);
    mPendingSendRequestTask.push_back(request);

    // wake up
    eventfd_write(mPollEventFd, 1);
}

void ConnectionManager::processPendingSendRequest() {
    // check connection state
    ConnectionState state;
    mConnectionLock.lock();
    state = mConnectionState;
    if (state != Connected) {
        LOGE(LOG_TAG, "processPendingSendRequest(), Is not connected");
        return;
    }
    mConnectionLock.unlock();

    std::lock_guard<std::mutex> lockTask(mSendRequestTaskLock); // lock guard. unlock auto
    if (mPendingSendRequestTask.empty()) {
        LOGE(LOG_TAG, "processPendingSendRequest(), Pending task is empty");
        return;
    }

    std::vector<ProtocolSendPtr>::iterator iterator = mPendingSendRequestTask.begin();
    ProtocolSend * request = (*iterator).get();
    NativeByteBuffer* requestBuffer = request->getBuffer();
    ssize_t sendCount = send(mSocketFd, requestBuffer->bytes() + requestBuffer->position(), requestBuffer->remaining(), NULL);
    if (sendCount < 0) {
        LOGE(LOG_TAG, "processPendingSendRequest(), Failed to send");
        mPendingSendRequestTask.erase(iterator);
        return;
    }

    LOGD(LOG_TAG, "processPendingSendRequest(), send finished [%d] [%d]", sendCount, requestBuffer->limit());

    requestBuffer->skip((uint32_t) sendCount);
    if (requestBuffer->hasRemaining() == false) {
        mPendingSendRequestTask.erase(iterator);
    }
}

#undef LOG_TAG