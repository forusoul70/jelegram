package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import jelegram.forusoul.com.ConstValues;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Request send code
 */

public class ReqAuthSendCode implements IProtocol {
    private final String mPhoneNumber;
    private final ByteArrayOutputStream mSerializeStream = new ByteArrayOutputStream();

    public ReqAuthSendCode(String phoneNumber) {
        mPhoneNumber = phoneNumber;
    }

    @Override
    public int getConstructor() {
        return Constructor.ReqSendCode.getConstructor();
    }

    @Override
    public boolean isHandshakeProtocol() {
        return false;
    }

    @Override
    public byte[] serializeSteam() {
        ByteUtils.writeInt32(mSerializeStream, getConstructor());
        try {
            ByteUtils.writeInt32(mSerializeStream, 0); // disallow flash call
            ByteUtils.writeByteAndLength(mSerializeStream, mPhoneNumber.getBytes("UTF-8"));
            ByteUtils.writeInt32(mSerializeStream, ConstValues.APP_ID);
            ByteUtils.writeByteAndLength(mSerializeStream, ConstValues.APP_HASH.getBytes("UTF-8"));
        } catch (IOException ignore) {

        }
        return mSerializeStream.toByteArray();
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) throws Exception {

    }
}
