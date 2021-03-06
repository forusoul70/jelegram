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
        ReqDHInner(0x6643b654),
        ResDHGenOK(0x3bcbf734),
        ReqSendCode(0x86aef0ec);

        private final int mValue;
        Constructor(int value) {
            mValue = value;
        }

        public int getConstructor() {
            return mValue;
        }
    }

    int getConstructor();
    boolean isHandshakeProtocol();
    byte[] serializeSteam();
    void readFromStream(@NonNull InputStream stream, int length) throws Exception;
}
