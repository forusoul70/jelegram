package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;

import java.io.InputStream;

/**
 * Protocol interface with server
 */

public interface IProtocol {
    public enum Constructor {
        ReqPQ(0x60469778),
        ResPQ(0x05162463),
        ResDH(0xd0e8075c),
        ResDHInner(0xb5890dba),
        ReqDH(0xf5045f1f),
        ReqDHInner(0x6643b654);

        private final int mValue;
        Constructor(int value) {
            mValue = value;
        }

        public int getConstructor() {
            return mValue;
        }
    }

    int getConstructor();
    byte[] serializeSteam();
    void readFromStream(@NonNull InputStream stream, int length) throws Exception;
}
