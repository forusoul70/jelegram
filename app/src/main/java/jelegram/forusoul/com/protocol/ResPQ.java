package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.InputStream;
import java.util.Locale;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Response PQ
 */

public class ResPQ implements IProtocol {
    private static final String TAG = "ResPQ";

    private final byte[] mNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];
    private byte[] mPQ = null;
    private long mServerPublicKeyFingerPrint = 0;

    @Override
    public int getConstructor() {
        return Constructor.ResPQ.getConstructor();
    }

    @Override
    public byte[] serializeSteam() {
        return new byte[0];
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) {
        try {
            int rc = stream.read(mNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read nonce [" + rc + "]");
                }
                return;
            }

            rc = stream.read(mServerNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read server nonce [" + rc + "]");
                }
                return;
            }

            mPQ = ByteUtils.readByteArray(stream);
            if (mPQ == null || mPQ.length != 8) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to pq [" + (mPQ == null ? 0 : mPQ.length) + "]");
                }
                return;
            }

            int magic = ByteUtils.readInt32(stream);
            if (magic != 0x1cb5c415) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, String.format(Locale.getDefault(), "readFromStream(), Invalid Vector magic [0x%x]", magic));
                }
                return;
            }

            int fingerPrintListCount = ByteUtils.readInt32(stream);
            if (fingerPrintListCount != 1) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, String.format(Locale.getDefault(), "readFromStream(), It should be invalid finger print count [%d]", fingerPrintListCount));
                }
                return;
            }
            mServerPublicKeyFingerPrint = ByteUtils.readInt64(stream);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream()", e);
            }
        }
    }

    public byte[] getPQ() {
        return mPQ;
    }

    public byte[] getNonce() {
        return mNonce;
    }

    public byte[] getServerNonce() {
        return mServerNonce;
    }

    public long getServerPublicKeyFingerPrint() {
        return mServerPublicKeyFingerPrint;
    }
}
