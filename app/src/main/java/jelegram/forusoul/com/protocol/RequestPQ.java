package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request pq for handshake
 */

public class RequestPQ implements IProtocol {
    private static final String TAG = "RequestPQ";

    private static final SecureRandom sRandom = new SecureRandom();
    private final int CONSTUCTOR = 0x60469778;
    private final byte[] mNonce = sRandom.generateSeed(16);
    private ByteArrayOutputStream mOutStream = new ByteArrayOutputStream();

    @Override
    public int getConstructor() {
        return Constructor.ReqPQ.getConstructor();
    }

    @Override
    public byte[] serializeSteam() {
        // message constructor
        ByteUtils.writeInt32(mOutStream, getConstructor());

        // random
        sRandom.nextBytes(mNonce);
        try {
            mOutStream.write(mNonce);
        } catch (IOException e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "I/O exception ", e);
            }
            return null;
        }
        return mOutStream.toByteArray();
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) {

    }
}
