package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;

/**
 * Response of diffie-hellman key success
 */

public class ResDHGenOk implements IProtocol {
    private static final String TAG = "ResDHGenOk";

    private final byte[] mClientNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];
    private final byte[] mNewNonceHash = new byte[16];

    @Override
    public int getConstructor() {
        return Constructor.ResDHGenOK.getConstructor();
    }

    @Override
    public byte[] serializeSteam() {
        return new byte[0];
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) throws Exception {
        int rc = stream.read(mClientNonce);
        if (rc != 16) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to read client nonce");
            }
            return;
        }

        rc = stream.read(mServerNonce);
        if (rc != 16) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to read sever nonce");
            }
            return;
        }

        rc = stream.read(mNewNonceHash);
        if (rc != 16) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream(), Failed to new nonce hash");
            }
        }
    }

    public byte[] getClientNonce() {
        return mClientNonce;
    }

    public byte[] getServerNonce() {
        return mServerNonce;
    }

    public byte[] getNewNonceHash() {
        return mNewNonceHash;
    }
}
