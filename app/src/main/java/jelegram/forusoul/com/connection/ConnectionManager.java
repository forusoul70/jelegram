package jelegram.forusoul.com.connection;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.security.acl.LastOwnerException;

import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.protocol.IProtocol;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Connection manager
 */

public class ConnectionManager {
    static {
        System.loadLibrary("native-lib");
    }

    private static final String TAG = "ConnectionManager";

    private boolean mIsFirstPacketSent = false;

    private static class SingletonHolder {
        static final ConnectionManager INSTANCE = new ConnectionManager();
    }

    public static ConnectionManager getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public void sendRequest(IProtocol protocol) throws Exception {
        if (protocol == null) {
            return;
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        if (mIsFirstPacketSent == false) {
            buffer.write(CipherManager.getInstance().getInitializeKeyReportData());
            mIsFirstPacketSent = true;
        }

        byte[] body = protocol.serializeSteam();
        int packetLength = body.length / 4;
        if (packetLength < 0x7f) {
            buffer.write(CipherManager.getInstance().encryptAesCtrModeNoPadding(new byte[]{(byte) packetLength}));
        } else {
            buffer.write(CipherManager.getInstance().encryptAesCtrModeNoPadding(ByteUtils.convertInt32(packetLength)));
        }
        buffer.write(CipherManager.getInstance().encryptAesCtrModeNoPadding(body));
        native_send_request(buffer.toByteArray());
    }

    public static void onByteReceived(byte[] message) {
        Log.i(TAG, "onByteReceived");
        ByteUtils.printByteBuffer(message);
    }

    public static native void native_send_request(byte[] request);
}
