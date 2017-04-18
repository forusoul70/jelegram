package jelegram.forusoul.com.connection;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.protocol.IProtocol;
import jelegram.forusoul.com.protocol.RequestPQ;
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

    private void onMessageReceived(@NonNull ByteArrayInputStream inputStream, int packLength) {
        try {
            long authKey = ByteUtils.readInt64(inputStream);
            long messageId = ByteUtils.readInt64(inputStream);
            int messageLength = ByteUtils.readInt32(inputStream);
            int protocolConstructor = ByteUtils.readInt32(inputStream);

            Log.d(TAG, "onMessageReceived(), auth key -- " + authKey);
            Log.d(TAG, "onMessageReceived(), message id -- " + messageId);
            Log.d(TAG, "onMessageReceived(), message length -- " + messageLength);
            Log.d(TAG, "onMessageReceived(), constrcutor -- " + protocolConstructor);

            if (protocolConstructor == IProtocol.Constructor.ReqPQ.getConstructor()) {
                RequestPQ requestPQ = new RequestPQ();
            }
        } catch (Exception e) {
            Log.e(TAG, "onByteReceived(), Failed to parse");
        }
    }

    public static void onByteReceived(byte[] message) {
        if (message == null || message.length == 0) {
            Log.e(TAG, "onByteReceived(), Input message is empty");
            return;
        }

        try {
            // Decryption
            byte[] decryptionMessage = CipherManager.getInstance().decryptAesCtrModeNoPadding(message);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(decryptionMessage);

            // find packet length
            int packLength = 0;
            int firstByte = inputStream.read();
            if (firstByte != 0x7f) {
                packLength = firstByte * 4;
            } else {
                if (decryptionMessage.length < 4) {
                    // TODO handle remain data;
                    Log.e(TAG, "We should receive remain data [" + decryptionMessage.length + "]");
                    return;
                }
                inputStream.reset();
                packLength = ByteUtils.readInt32(inputStream);
            }

            // check packet length validation
            if (packLength > inputStream.available()) {
                Log.e(TAG, String.format("onByteReceived(), Invalid packet length [%d] [%d]", packLength, inputStream.available()));
                // TODO handle remain data
                return;
            }

            ByteUtils.printByteBuffer(decryptionMessage);
        } catch (Exception e) {
            Log.e(TAG, "onByteReceived(), Failed to parse");
        }
    }

    public static native void native_send_request(byte[] request);
}
