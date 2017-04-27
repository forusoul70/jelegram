package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request for DH Key Exchange
 */

public class ReqDHParams implements IProtocol {
    private static final String TAG = "ReqDHParams";
    private final byte[] mClientNonce;
    private final byte[] mServerNonce;
    private final byte[] mPQ;
    private final byte[] mNewNonce;
    private final long mServerPublicKeyFingerPrint;

    private ReqPQInnerData mInnerData = null;

    private ByteArrayOutputStream mOutStream = new ByteArrayOutputStream();

    public ReqDHParams(byte[] clientNonce, byte[] serverNonce, byte[] newNonce, byte[] pq, long serverPublicKeyFingerPrint) {
        mClientNonce = clientNonce;
        mServerNonce = serverNonce;
        mPQ = pq;
        mNewNonce = newNonce;
        mServerPublicKeyFingerPrint = serverPublicKeyFingerPrint;
    }

    @Override
    public int getConstructor() {
        return 0xd712e4be;
    }

    @Override
    public boolean isHandshakeProtocol() {
        return true;
    }

    @Override
    public byte[] serializeSteam() {
        try {
            int[] pq = CipherManager.factorizePQ(mPQ);
            if (pq == null || pq.length < 2) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "executeDHKeyExchange(), Failed to factorize pq ");
                }
                return null;
            }
            byte[] p = new byte[] {(byte)(pq[0] >> 24), (byte)(pq[0] >> 16), (byte)(pq[0] >> 8), (byte)(pq[0])};
            byte[] q = new byte[] {(byte)(pq[1] >> 24), (byte)(pq[1] >> 16), (byte)(pq[1] >> 8), (byte)(pq[1])};

            SecureRandom random = new SecureRandom();
            ByteUtils.writeInt32(mOutStream, getConstructor());
            mOutStream.write(mClientNonce);
            mOutStream.write(mServerNonce);
            ByteUtils.writeByteAndLength(mOutStream, p);
            ByteUtils.writeByteAndLength(mOutStream, q);

            ByteUtils.writeInt64(mOutStream, mServerPublicKeyFingerPrint);

            // Inner data
            ByteArrayOutputStream innerOutputStream = new ByteArrayOutputStream();
            mInnerData = new ReqPQInnerData(mClientNonce, mServerNonce, mNewNonce, mPQ, p, q);
            byte[] innerBytes = mInnerData.serializeSteam();
            if (innerBytes == null || innerBytes.length == 0) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "executeDHKeyExchange(), Failed to serialize inner rq request");
                }
                return null;
            }

            byte[] messageDigest = CipherManager.getInstance().requestSha1(innerBytes);
            if (messageDigest == null || messageDigest.length == 0) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "executeDHKeyExchange(), Failed to make message digest");
                }
                return null;
            }

            innerOutputStream.write(messageDigest);
            innerOutputStream.write(innerBytes);
            if (innerOutputStream.size() < 255) {
                innerOutputStream.write(random.generateSeed(255 - innerOutputStream.size()));
            }

            byte[] rasEncryption = CipherManager.getInstance().requestEncryptRsa(mServerPublicKeyFingerPrint, innerOutputStream.toByteArray());
            if (rasEncryption == null || rasEncryption.length == 0) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "serializeSteam(), Failed to rsa encryption");
                }
                return null;
            }
            ByteUtils.writeByteAndLength(mOutStream, rasEncryption);
            return mOutStream.toByteArray();
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "serializeSteam()", e);
            }
            return null;
        }
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) {

    }
}
