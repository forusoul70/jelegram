package jelegram.forusoul.com.connection;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Locale;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.protocol.IProtocol;
import jelegram.forusoul.com.protocol.ReqDHParams;
import jelegram.forusoul.com.protocol.ReqMessageAck;
import jelegram.forusoul.com.protocol.ResDHParam;
import jelegram.forusoul.com.protocol.ResPQ;
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

    private static final Object AUTH_KEY_LOCK = new Object();

    private byte[] mNewNonce = null;
    private long mAuthKey = 0;

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

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        // auth key_id ....
        synchronized (AUTH_KEY_LOCK) {
            ByteUtils.writeInt64(body, mAuthKey);
        }

        // message id
        ByteUtils.writeInt64(body, System.currentTimeMillis() / 1000L);

        // message
        byte[] message = protocol.serializeSteam();
        if (message == null || message.length == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "sendRequest(), Failed to serialize stream");
            }
            return;
        }
        ByteUtils.writeInt32(body, message.length);
        body.write(message);

        ByteArrayOutputStream encryptedMessageStream = new ByteArrayOutputStream();
        if (mIsFirstPacketSent == false) {
            encryptedMessageStream.write(CipherManager.getInstance().getInitializeKeyReportData());
            mIsFirstPacketSent = true;
        }

        if (BuildConfig.DEBUG) {
            Log.i(TAG, "----------Send request ------------");
            ByteUtils.printByteBuffer(body.toByteArray());
            Log.i(TAG, "----------End request ------------");
        }

        int packetLength = body.size() / 4;
        if (packetLength < 0x7f) {
            encryptedMessageStream.write(CipherManager.getInstance().encryptAesMessage(new byte[]{(byte) packetLength}));
        } else {
            encryptedMessageStream.write(CipherManager.getInstance().encryptAesMessage(ByteUtils.convertInt32(packetLength)));
        }
        encryptedMessageStream.write(CipherManager.getInstance().encryptAesMessage(body.toByteArray()));
        native_send_request(encryptedMessageStream.toByteArray());
    }

    private void onMessageReceived(@NonNull ByteArrayInputStream inputStream, int packLength) {
        try {
            long authKey = ByteUtils.readInt64(inputStream);
            long messageId = ByteUtils.readInt64(inputStream);
            int messageLength = ByteUtils.readInt32(inputStream);
            int protocolConstructor = ByteUtils.readInt32(inputStream);

            if (BuildConfig.DEBUG) {
                Log.d(TAG, "onMessageReceived(), auth key -- " + authKey);
                Log.d(TAG, "onMessageReceived(), message id -- " + messageId);
                Log.d(TAG, "onMessageReceived(), message length -- " + messageLength);
                Log.d(TAG, String.format(Locale.getDefault(), "onMessageReceived(), constructor -- 0x%x", protocolConstructor));
            }

            if (protocolConstructor == IProtocol.Constructor.ResPQ.getConstructor()) {
                // first ack
                ReqMessageAck ack = new ReqMessageAck(messageId);
                sendRequest(ack);

                ResPQ resPQ = new ResPQ();
                resPQ.readFromStream(inputStream, messageLength);
                executeRequestDHParam(resPQ);
            } else if (protocolConstructor == IProtocol.Constructor.ResDH.getConstructor()) {
                if (mNewNonce == null || mNewNonce.length == 0) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "onMessageReceived(), Current new nonce is empty");
                    }
                    return;
                }
                ResDHParam resDHParam = new ResDHParam(mNewNonce);
                resDHParam.readFromStream(inputStream, messageLength);
                executeOnResponseDHParam(resDHParam);
            }
        } catch (Exception e) {
            Log.e(TAG, "onByteReceived(), Failed to parse");
        }
    }

    private void executeRequestDHParam(ResPQ resPQ) {
        if (resPQ == null) {
            return;
        }

        // first ack
        ReqDHParams reqDH = new ReqDHParams(resPQ.getNonce(), resPQ.getServerNonce(), resPQ.getPQ(), resPQ.getServerPublicKeyFingerPrint());
        try {
            sendRequest(reqDH);
            mNewNonce = reqDH.getNewNonce();
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeRequestDHParam()", e);
            }
        }
    }

    private void executeOnResponseDHParam(ResDHParam resDHParam) {

    }

    public static void onByteReceived(byte[] message) {
        if (message == null || message.length == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "onByteReceived(), Input message is empty");
            }
            return;
        }

        try {
            // Decryption
            byte[] decryptionMessage = CipherManager.getInstance().decryptAesCtrModeNoPadding(message);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(decryptionMessage);
            inputStream.mark(-1); // mark position 0, -1 은 의미 없음

            // find packet length
            int packLength = 0;
            int firstByte = inputStream.read();
            if (firstByte != 0x7f) {
                packLength = firstByte * 4;
            } else {
                if (decryptionMessage.length < 4) {
                    // TODO handle remain data;
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "We should receive remain data [" + decryptionMessage.length + "]");
                    }
                    return;
                }
                inputStream.reset(); // reset position to 0
                packLength = (ByteUtils.readInt32(inputStream) >> 8) * 4;
            }

            // check packet length validation
            if (packLength > inputStream.available()) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, String.format("onByteReceived(), Invalid packet length [%d] [%d]", packLength, inputStream.available()));
                }
                // TODO handle remain data
                return;
            }

            if (BuildConfig.DEBUG) {
                Log.i(TAG, "----------Received message ------------");
                ByteUtils.printByteBuffer(decryptionMessage);
                Log.i(TAG, "----------End received ------------");
            }

            getInstance().onMessageReceived(inputStream, packLength);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "onByteReceived(), Failed to parse", e);
            }
        }
    }

    private static native void native_send_request(byte[] request);
}
