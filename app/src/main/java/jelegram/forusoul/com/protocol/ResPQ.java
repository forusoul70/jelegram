package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.InputStream;

import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Response PQ
 */

public class ResPQ implements IProtocol {
    private static final String TAG = "ResPQ";
    private final byte[] mNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];

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
                Log.e(TAG, "readFromStream(), Failed to read nonce");
                return;
            }

            rc = stream.read(mServerNonce);
            if (rc != 16) {
                Log.e(TAG, "readFromStream(), Failed to read server nonce");
                return;
            }



        } catch (Exception e) {
            Log.e(TAG, "readFromStream()", e);
        }
    }
}
