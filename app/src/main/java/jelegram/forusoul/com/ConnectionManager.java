package jelegram.forusoul.com;

/**
 * Connection manager
 */

public class ConnectionManager {
    static {
        System.loadLibrary("native-lib");
    }

    private static class SingletonHolder {
        static final ConnectionManager INSTANCE = new ConnectionManager();
    }

    public static ConnectionManager getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public void sendRequest(byte[] request) {
        if (request == null || request.length < 0) {
            return;
        }

        native_send_request(request);
    }


    public static native void native_send_request(byte[] request);
}
