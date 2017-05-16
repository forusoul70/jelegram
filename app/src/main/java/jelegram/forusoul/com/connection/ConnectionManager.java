package jelegram.forusoul.com.connection;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
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

    private static class ServerSalt {
        long validSince = 0L;
        long validUntil = 0L;
        long serverSalt = -1L;
    }

    private static final String TAG = "ConnectionManager";

    private final SecureRandom mSecureRandom = new SecureRandom();

    private boolean mIsFirstPacketSent = false;
    private byte[] mClientNonce = null;
    private byte[] mServerNonce = null;
    private byte[] mAuthNewNonce = null;
    private byte[] mHandshakeAuthKey = null;

    private final Object HANDSHAKE_STATE_LOCK = new Object();
    private boolean mIsHandshakeFinished = false;
    private byte[] mAuthKey = null;
    private long mAuthKeyId = 0L;

    private final ArrayList<IProtocol> mPendingRequestList = new ArrayList<>();
    private final ArrayList<ServerSalt> mServerSaltList = new ArrayList<>();

    private static class SingletonHolder {
        static final ConnectionManager INSTANCE = new ConnectionManager();
    }

    public static ConnectionManager getInstance() {
        return SingletonHolder.INSTANCE;
    }

    private ConnectionManager() {
        executeBeginHandshake();
    }

    public void requestSenApi(IProtocol protocol) {
        if (protocol == null) {
            return;
        }


    }

    private long generateMessageId() {
        return System.currentTimeMillis() / 1000;
    }

    private byte[] createProtocolData(IProtocol protocol) {
        if (protocol == null) {
            return null;
        }

        long authKeyId = -1L;
        synchronized (HANDSHAKE_STATE_LOCK) {
            if (mIsHandshakeFinished == false) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "createProtocolData(), Handshake is not finished");
                }
                return null;
            }

            authKeyId = mAuthKeyId;
            if (authKeyId == 0L) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "createProtocolData(), Current auth key is 0");
                }
                return null;
            }
        }

        if (protocol.isHandshakeProtocol()) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "createProtocolData(), Request protocol is handshake protocol");
            }
            return null;
        }
        // TODO
        /* see Datacenter::createRequestsData
         * buffer->writeInt64(authKeyId);
            buffer->position(24);

            buffer->writeInt64(getServerSalt());
            buffer->writeInt64(connection->getSissionId());
            buffer->writeInt64(messageId);
            buffer->writeInt32(messageSeqNo);
            buffer->writeInt32(messageSize);
            messageBody->serializeToStream(buffer);

            SHA1(buffer->bytes() + 24, 32 + messageSize, messageKey + 4); /in, inputLength, out
         */
        ByteArrayOutputStream protocolStream = new ByteArrayOutputStream();
        long messageId = generateMessageId();
        ByteUtils.writeInt64(protocolStream, authKeyId);

        return protocolStream.toByteArray();
    }

    private void sendRequest(IProtocol protocol) throws Exception {
        if (protocol == null) {
            return;
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        synchronized (HANDSHAKE_STATE_LOCK) {
            if (mIsHandshakeFinished == false && protocol.isHandshakeProtocol() == false) {
                if (BuildConfig.DEBUG) {
                    Log.d(TAG, "sendRequest(), Pending request, because of handshaking status");
                }
                mPendingRequestList.add(protocol);
                return;
            }

            // auth key_id ....
            body.write(mAuthKey);
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
                mAuthKey = new byte[8];
                Arrays.fill(mAuthKey, (byte)0);

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
        ArrayList<byte[]> gAndGbResult = CipherManager.getInstance().requestCalculateDiffieHellmanGB(resDHParam.getDHPrime(), resDHParam.getG(), resDHParam.getGA());
        if (gAndGbResult == null || gAndGbResult.isEmpty()) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "executeOnResponseDHParam(), Failed to calculate gb");
            }
            return;
        }
        byte[] b = gAndGbResult.get(0);
        byte[] gB = gAndGbResult.get(1);

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
            byte[] authKey = CipherManager.getInstance().requestCalculateModExp(resDHParam.getGA(), b, resDHParam.getDHPrime());
            if (authKey == null || authKey.length == 0){
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "executeOnResponseDHParam(), Failed to calculate hash key");
                }
                return;
            }

            if (authKey.length < 256) {
                mHandshakeAuthKey = new byte[256];
                Arrays.fill(mHandshakeAuthKey, (byte)0);
                System.arraycopy(authKey, 0, mHandshakeAuthKey, 256 - authKey.length, authKey.length);
            } else {
                mHandshakeAuthKey = authKey;
            }

            // add server salt
            long currentTime = System.currentTimeMillis() / 1000;
            long timeDifference = resDHParam.getServerTime() - currentTime;
            ServerSalt salt = new ServerSalt();
            salt.validSince = currentTime + timeDifference -5;
            salt.validUntil = salt.validSince + 30 * 60;
            for (int i = 7; i >=0; i++) {
                salt.serverSalt <<= 8;
                salt.serverSalt |= (mClientNonce[i] ^ mServerNonce[i]);
            }
            mServerSaltList.add(salt);
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

        if (mHandshakeAuthKey == null || mHandshakeAuthKey.length == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "Current handshake auth key is empty");
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
        authKeyAuxHashBuffer.write(CipherManager.getInstance().requestSha1(mHandshakeAuthKey));
        byte[] authKeyBuffer = authKeyAuxHashBuffer.toByteArray();
        authKeyAuxHashBuffer.write(CipherManager.getInstance().requestSha1(Arrays.copyOfRange(authKeyBuffer, 0, authKeyBuffer.length - 12)));

        // handshake finished
        synchronized (HANDSHAKE_STATE_LOCK) {
            // TODO check DH answer nonce hash

            mAuthKey = mHandshakeAuthKey;
            mAuthKeyId = ByteUtils.convertByte8(Arrays.copyOfRange(authKeyBuffer, authKeyBuffer.length - 8, authKeyBuffer.length));
            mHandshakeAuthKey = null;
            mIsHandshakeFinished = true;

            if (BuildConfig.DEBUG) {
                Log.d(TAG, "Handshake success");
            }
        }
    }

    private void addServerSalt(ServerSalt serverSalt) {
        for (ServerSalt salt : mServerSaltList) {
            if (salt.serverSalt == serverSalt.serverSalt) {
                return;
            }
        }
        mServerSaltList.add(serverSalt);
    }

    private ServerSalt getServerSalt() {
        long currentTime = System.currentTimeMillis();

        int size = mServerSaltList.size();
        long maxRemainingInterval = 0;
        ServerSalt result = null;

        for (int i = size -1; i >=0; i--) {
            ServerSalt salt = mServerSaltList.get(i);
            if (salt.validUntil < currentTime) {
                mServerSaltList.remove(i);
            } else if (salt.validSince <= currentTime && salt.validUntil > currentTime){
                if (maxRemainingInterval == 0 || Math.abs(salt.validUntil - currentTime) > currentTime) {
                    maxRemainingInterval = Math.abs(salt.validUntil - currentTime);
                    result = salt;
                }
            }
        }
        return result;
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
