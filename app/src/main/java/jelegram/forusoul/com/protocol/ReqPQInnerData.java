package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request for DH Key exchange inner data
 */

public class ReqPQInnerData implements IProtocol {
    private static final String TAG = "ReqPQInnerData";
    private ByteArrayOutputStream mOutStream = new ByteArrayOutputStream();

    private final byte[] mClientNonce;
    private final byte[] mServerNonce;
    private final byte[] mNewNonce;
    private final byte[] mMultiplyPQ;
    private final byte[] mP;
    private final byte[] mQ;

    public ReqPQInnerData(byte[] clientNonce, byte[] serverNonce, byte[] newNonce, byte[] multiplyPQ, byte[] p, byte[] q) {
        mClientNonce = clientNonce;
        mServerNonce = serverNonce;
        mNewNonce = newNonce;
        mMultiplyPQ = multiplyPQ;
        mP = p;
        mQ = q;
    }

    @Override
    public int getConstructor() {
        return 0x83c95aec;
    }

    @Override
    public byte[] serializeSteam() {
        try {
            ByteUtils.writeInt32(mOutStream, getConstructor());
            ByteUtils.writeByteAndLength(mOutStream, mMultiplyPQ);
            ByteUtils.writeByteAndLength(mOutStream, mP);
            ByteUtils.writeByteAndLength(mOutStream, mQ);
            mOutStream.write(mClientNonce);
            mOutStream.write(mServerNonce);
            mOutStream.write(mNewNonce);
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
