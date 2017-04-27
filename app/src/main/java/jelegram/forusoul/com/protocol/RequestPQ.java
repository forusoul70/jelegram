package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request pq for handshake
 */

public class RequestPQ implements IProtocol {
    private static final String TAG = "RequestPQ";

    private final byte[] mClientNonce;
    private ByteArrayOutputStream mOutStream = new ByteArrayOutputStream();

    public RequestPQ(byte[] clientNonce) {
        mClientNonce = clientNonce;
    }

    @Override
    public int getConstructor() {
        return Constructor.ReqPQ.getConstructor();
    }

    @Override
    public boolean isHandshakeProtocol() {
        return true;
    }

    @Override
    public byte[] serializeSteam() {
        // message constructor
        ByteUtils.writeInt32(mOutStream, getConstructor());
        try {
            mOutStream.write(mClientNonce);
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
