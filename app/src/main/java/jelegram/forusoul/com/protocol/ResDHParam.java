package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Response of DH param
 */

public class ResDHParam implements IProtocol {

    private static final String TAG = "ResDHParam";

    private final byte[] mClientNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];
    private int mG = 0;
    private byte[] mDHPrime = null;
    private byte[] mGPowA = null;
    private int mServerTime = 0;

    @Override
    public int getConstructor() {
        return 0xd0e8075c;
    }

    @Override
    public byte[] serializeSteam() {
        return null;
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) {
        try {
            int rc = stream.read(mClientNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read nonce [" + rc + "]");

                }
            }

            rc = stream.read(mServerNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read server nonce [" + rc + "]");

                }
            }

            mG = ByteUtils.readInt32(stream);
            mDHPrime = ByteUtils.readByteArray(stream);
            mGPowA = ByteUtils.readByteArray(stream);
            mServerTime = ByteUtils.readInt32(stream);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream()", e);
            }
        }
    }


    public byte[] getClientNonce() {
        return mClientNonce;
    }

    public byte[] getServerNonce() {
        return mServerNonce;
    }

}
