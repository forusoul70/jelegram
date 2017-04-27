package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.ArrayList;

import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Message ack
 */

public class ReqMessageAck implements IProtocol {

    private final ByteArrayOutputStream mOutputStream = new ByteArrayOutputStream();
    private ArrayList<Long> mAckMessageList = new ArrayList<>();

    public ReqMessageAck(long messageId) {
        mAckMessageList.add(messageId);
    }

    @Override
    public int getConstructor() {
        return 0x62d6b459;
    }

    @Override
    public boolean isHandshakeProtocol() {
        return true;
    }

    @Override
    public byte[] serializeSteam() {
        ByteUtils.writeInt32(mOutputStream, getConstructor());
        ByteUtils.writeInt32(mOutputStream, 0x1cb5c415); // magic vector
        ByteUtils.writeInt32(mOutputStream, mAckMessageList.size());
        for (Long messageId : mAckMessageList) {
            ByteUtils.writeInt64(mOutputStream, messageId);
        }
        return mOutputStream.toByteArray();
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) {

    }
}
