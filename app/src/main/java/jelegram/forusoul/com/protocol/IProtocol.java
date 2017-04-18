package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;

import java.io.InputStream;

/**
 * Protocol interface with server
 */

public interface IProtocol {
    public enum Constructor {
        ReqPQ(0x60469778),
        ResPQ(0x05162463);

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
    void readFromStream(@NonNull InputStream stream, int length);
}
