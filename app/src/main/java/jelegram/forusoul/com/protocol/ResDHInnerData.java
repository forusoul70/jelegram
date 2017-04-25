package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Res Inner data
 */

public class ResDHInnerData implements IProtocol {
    private static final String TAG = "ResDHInnerData";

    private final byte[] mClientNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];
    private int mG = -1;
    private byte[] mDHPrime = null;
    private byte[] mGA = null;
    private int mServerTime = 0;

    @Override
    public int getConstructor() {
        return 0xb5890dba;
    }

    @Override
    public byte[] serializeSteam() {
        return new byte[0];
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) throws Exception {
        if (stream.read(mClientNonce) != 16) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to load client nonce");
            }
            return;
        }

        if (stream.read(mServerNonce) != 16) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to load server nonce");
            }
            return;
        }

        mG = ByteUtils.readInt32(stream);
        mDHPrime = ByteUtils.readByteArray(stream);
        if (mDHPrime == null) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to load dh prime");
            }
            return;
        }

        mGA = ByteUtils.readByteArray(stream);
        if (mGA == null) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to g pow a");
            }
            return;
        }

        mServerTime = ByteUtils.readInt32(stream);
    }

    public byte[] getClientNonce() {
        return mClientNonce;
    }

    public byte[] getServerNonce() {
        return mServerNonce;
    }

    public byte[] getDHPrime() {
        return mDHPrime;
    }

    public byte[] getGA() {
        return mGA;
    }

    public int getG() {
        return mG;
    }
}
