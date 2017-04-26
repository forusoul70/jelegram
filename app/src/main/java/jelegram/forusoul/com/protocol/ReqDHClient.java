package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request client Diffie-Hellman key exchange
 */

public class ReqDHClient implements IProtocol {
    private static final String TAG = "ReqDHClient";

    private final ByteArrayOutputStream mOutputStream = new ByteArrayOutputStream();

    private final byte[] mClientNonce;
    private final byte[] mServerNonce;
    private final byte[] mGb;
    private final byte[] mAgeKey;
    private final byte[] mAgeIv;

    public ReqDHClient(byte[] clientNonce, byte[] serverNonce, byte[] gb, byte[] ageEncryptionKey, byte[] ageEncryptionIv) {
        mClientNonce = clientNonce;
        mServerNonce = serverNonce;
        mGb = gb;
        mAgeKey = ageEncryptionKey;
        mAgeIv = ageEncryptionIv;
    }

    @Override
    public int getConstructor() {
        return Constructor.ReqDH.getConstructor();
    }

    @Override
    public byte[] serializeSteam() {
        try {
            ByteUtils.writeInt32(mOutputStream, getConstructor());
            mOutputStream.write(mClientNonce);
            mOutputStream.write(mServerNonce);

            ReqClientInnerData reqClientInnerData = new ReqClientInnerData(mClientNonce, mServerNonce, mGb);
            byte[] clientInnerBytes = CipherManager.getInstance().encryptAesIge(reqClientInnerData.serializeSteam(), mAgeKey, mAgeIv);
            if (clientInnerBytes == null || clientInnerBytes.length == 0) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "serializeSteam(), Failed to encrypt inner data");
                }
                return null;
            }
            ByteUtils.writeByteAndLength(mOutputStream, clientInnerBytes);

            return mOutputStream.toByteArray();
        } catch (IOException e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "serializeSteam()", e);
            }
            return null;
        }
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) throws Exception {

    }
}
