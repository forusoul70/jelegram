package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request diffie-hellman client inner data
 */

public class ReqClientInnerData implements IProtocol {
    private static final String TAG = "ReqClientInnerData";

    private ByteArrayOutputStream mOutputStream = new ByteArrayOutputStream();
    private final byte[] mClientNonce;
    private final byte[] mServerNonce;
    private byte[] mGb = null;
    private final int mRetryCount;

    public ReqClientInnerData(byte[] clientNonce, byte[] serverNonce, byte[] gB) {
        mClientNonce = clientNonce;
        mServerNonce = serverNonce;
        mGb = gB;
        mRetryCount = 0;
    }

    @Override
    public int getConstructor() {
        return Constructor.ReqDHInner.getConstructor();
    }

    @Override
    public byte[] serializeSteam() {
        if (mGb == null || mGb.length == 0) {
            return null;
        }

        try {
            ByteUtils.writeInt32(mOutputStream, getConstructor());
            mOutputStream.write(mClientNonce);
            mOutputStream.write(mServerNonce);
            ByteUtils.writeInt64(mOutputStream, mRetryCount);
            ByteUtils.writeByteAndLength(mOutputStream, mGb);

            byte[] innerData = mOutputStream.toByteArray();
            // message digest
            mOutputStream.write(CipherManager.getInstance().requestSha1(innerData));
            // message padding
            int paddingSize = (innerData.length + CipherManager.SHA_DIGEST_LENGTH) % 16;
            if (paddingSize > 0) {
                SecureRandom random = new SecureRandom();
                mOutputStream.write(random.generateSeed((16 - paddingSize)));
            }
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
