package jelegram.forusoul.com.connection;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.protocol.IProtocol;
import jelegram.forusoul.com.protocol.ReqDHClient;
import jelegram.forusoul.com.protocol.ReqDHParams;
import jelegram.forusoul.com.protocol.ReqMessageAck;
import jelegram.forusoul.com.protocol.RequestPQ;
import jelegram.forusoul.com.protocol.ResDHGenOk;
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

    private final SecureRandom mSecureRandom = new SecureRandom();

    private boolean mIsFirstPacketSent = false;
    private byte[] mClientNonce = null;
    private byte[] mServerNonce = null;
    private byte[] mAuthNewNonce = null;
    private byte[] mHandshakeAuthKey = null;

    private static final Object AUTH_KEY_LOCK = new Object();
    private long mAuthKey = 0;

    private final Object HANDSHAKE_STATE_LOCK = new Object();
    private boolean mIsHandshakeFinished = false;

    private static class SingletonHolder {
        static final ConnectionManager INSTANCE = new ConnectionManager();
    }

    public static ConnectionManager getInstance() {
        return SingletonHolder.INSTANCE;
    }

    private ConnectionManager() {
        executeBeginHandshake();
    }

    private void sendRequest(IProtocol protocol) throws Exception {
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
            packetLength = (packetLength << 8) + 0x7f;
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

                synchronized (HANDSHAKE_STATE_LOCK) {
                    ResPQ resPQ = new ResPQ();
                    resPQ.readFromStream(inputStream, messageLength);
                    mServerNonce = resPQ.getServerNonce();
                    executeRequestDHParam(resPQ);
                }
            } else if (protocolConstructor == IProtocol.Constructor.ResDH.getConstructor()) {
                if (mAuthNewNonce == null || mAuthNewNonce.length == 0) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "onMessageReceived(), Current new nonce is empty");
                    }
                    return;
                }

                synchronized (HANDSHAKE_STATE_LOCK) {
                    ResDHParam resDHParam = new ResDHParam(mAuthNewNonce);
                    resDHParam.readFromStream(inputStream, messageLength);
                    executeOnResponseDHParam(resDHParam, messageId);
                }
            } else if (protocolConstructor == IProtocol.Constructor.ResDHGenOK.getConstructor()) {
                if (mClientNonce == null || mClientNonce.length == 0 || mServerNonce == null || mServerNonce.length == 0) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "onMessageReceived(), Current  client or server nonce is empty");
                    }
                    return;
                }

                if (mAuthNewNonce == null || mAuthNewNonce.length == 0) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "onMessageReceived(), Current new nonce is empty");
                    }
                    return;
                }

                synchronized (HANDSHAKE_STATE_LOCK) {
                    ResDHGenOk resDHGenOk = new ResDHGenOk();
                    resDHGenOk.readFromStream(inputStream, messageLength);
                    executeOnDHGenerateSuccess(resDHGenOk, messageId);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "onByteReceived(), Failed to parse");
        }
    }

    private void executeBeginHandshake() {
        synchronized (HANDSHAKE_STATE_LOCK) {
            if (mIsHandshakeFinished == false) {
                SecureRandom random = new SecureRandom();
                mClientNonce = random.generateSeed(16);
                RequestPQ requestPQ = new RequestPQ(mClientNonce);
                try {
                    sendRequest(requestPQ);
                } catch (Exception e) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "executeBeginHandshake()", e);
                    }
                }
            }
        }
    }

    private void executeRequestDHParam(ResPQ resPQ) {
        if (resPQ == null) {
            return;
        }

        try {
            mAuthNewNonce = mSecureRandom.generateSeed(32);
            ReqDHParams reqDH = new ReqDHParams(resPQ.getNonce(), resPQ.getServerNonce(), mAuthNewNonce, resPQ.getPQ(), resPQ.getServerPublicKeyFingerPrint());
            sendRequest(reqDH);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeRequestDHParam()", e);
            }
        }
    }

    private void executeOnResponseDHParam(ResDHParam resDHParam, long messageId) {
        if (resDHParam == null) {
            return;
        }

        if (Arrays.equals(mClientNonce, resDHParam.getClientNonce()) == false) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), invalid client nonce");
            }
            return;
        }

        if (Arrays.equals(mServerNonce, resDHParam.getServerNonce()) == false) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), invalid server nonce");
            }
            return;
        }

        // find g^b mod p
        byte[] gB = CipherManager.getInstance().requestCalculateDiffieHellmanGB(resDHParam.getDHPrime(), resDHParam.getG(), resDHParam.getGA());
        if (gB == null || gB.length == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), Failed to calculate gb");
            }
            return;
        }

        // first ack
        ReqMessageAck ack = new ReqMessageAck(messageId);
        try {
            sendRequest(ack);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), Failed to send ack");
            }
            return;
        }

        ReqDHClient dhClient = new ReqDHClient(mClientNonce, mServerNonce, gB, resDHParam.getDecryptionKey(), resDHParam.getDecryptionIV());
        try {
            sendRequest(dhClient);

            // init handshake auth key
            mHandshakeAuthKey = new byte[256];

        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), Failed to send dh exchange client");
            }
        }
    }

    private void executeOnDHGenerateSuccess(ResDHGenOk resDHGenOk, long messageId) throws IOException {
        if (resDHGenOk == null) {
            return;
        }

        if (Arrays.equals(mClientNonce, resDHGenOk.getClientNonce()) == false) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnDHGenerateSuccess(), invalid client nonce");
            }
            return;
        }

        if (Arrays.equals(mServerNonce, resDHGenOk.getServerNonce()) == false) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnDHGenerateSuccess(), invalid server nonce");
            }
            return;
        }

        // first send ack
        try {
            sendRequest(new ReqMessageAck(messageId));
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnDHGenerateSuccess(), Failed to send ack");
            }
            return;
        }

        ByteArrayOutputStream authKeyAuxHashBuffer = new ByteArrayOutputStream();
        authKeyAuxHashBuffer.write(mAuthNewNonce);
        authKeyAuxHashBuffer.write(1);

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
