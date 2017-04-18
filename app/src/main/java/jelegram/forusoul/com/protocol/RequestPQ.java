package jelegram.forusoul.com.protocol;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

/**
 * Request pq for handshake
 */

public class RequestPQ implements IProtocol {
    private static final SecureRandom sRandom = new SecureRandom();
    private final int CONSTUCTOR = 0x60469778;
    private final byte[] mNonce = sRandom.generateSeed(16);
    private ByteArrayOutputStream mOutStream = new ByteArrayOutputStream();

    @Override
    public byte[] serializeSteam() {
        mOutStream.write(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0xc8, (byte)0x4b, (byte)0xf7, (byte)0x8f, (byte)0xf7, (byte)0xee, (byte)0x58,
                (byte)0x14, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x78, (byte)0x97, (byte)0x46, (byte)0x60,
                (byte)0x42, (byte)0xc1, (byte)0xb6, (byte)0x9c, (byte)0xfd, (byte)0x61, (byte)0x2d, (byte)0x0f,
                (byte)0xde, (byte)0xeb, (byte)0x0b, (byte)0xb4, (byte)0xf6, (byte)0x4c, (byte)0x4e, (byte)0xa3
        }, 0, 40);

        return mOutStream.toByteArray();
    }
}
