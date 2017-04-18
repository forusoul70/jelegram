package jelegram.forusoul.com.utils;

import android.support.annotation.VisibleForTesting;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Locale;

/**
 * Byte utils
 */

public class ByteUtils {
    private static final String TAG = "ByteUtils";

    public static int readInt32(ByteArrayInputStream inputStream) throws IOException {
        byte[] bytes = new byte[4];
        int readCount = inputStream.read(bytes);
        if (readCount != 4) {
            throw new IOException("readInt32(), Failed to read 4 bytes. Read count is " + readCount);
        }
        return bytes[0] & 0xff |
                (bytes[1] & 0xff) << 8 |
                (bytes[2] & 0xff) << 16 |
                (bytes[3] & 0xff) << 24;
    }

    public static long readInt64(ByteArrayInputStream inputStream) throws IOException {
        byte[] bytes = new byte[8];
        int readCount = inputStream.read(bytes);
        if (readCount != 8) {
            throw new IOException("readInt64(), Failed to read 4 bytes. Read count is " + readCount);
        }
        return bytes[0] & 0xff |
                (bytes[1] & 0xff) << 8 |
                (bytes[2] & 0xff) << 16 |
                (bytes[3] & 0xff) << 24 |
                ((long)(bytes[4]) & 0xff) << 32 |
                ((long)bytes[5] & 0xff) << 40 |
                ((long)bytes[6] & 0xff) << 48 |
                ((long)bytes[7] & 0xff) << 56;
    }

    public static void writeByte(ByteArrayOutputStream outputStream, int value) {
        outputStream.write(convertInt8(value), 0, 1);
    }

    public static void writeInt32(ByteArrayOutputStream outputStream, int value) {
        outputStream.write(convertInt32(value), 0, 4);
    }

    public static void writeInt64(ByteArrayOutputStream outputStream, long value) {
        byte[] bytes = new byte[8];
        bytes[0] = (byte) value;
        bytes[1] = (byte) (value >> 8);
        bytes[2] = (byte) (value >> 16);
        bytes[3] = (byte) (value >> 24);
        bytes[4] = (byte) (value >> 32);
        bytes[5] = (byte) (value >> 40);
        bytes[6] = (byte) (value >> 48);
        bytes[7] = (byte) (value >> 56);
        outputStream.write(bytes, 0, 8);
    }

    public static byte[] convertInt32(int value) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) value;
        bytes[1] = (byte) (value >> 8);
        bytes[2] = (byte) (value >> 16);
        bytes[3] = (byte) (value >> 24);
        return bytes;
    }

    public static byte[] convertInt8(int value) {
        byte[] bytes = new byte[1];
        bytes[0] = (byte) value;
        return bytes;
    }

    public static void printByteBuffer(byte[] buffer) {
        // Debug
        StringBuilder builder = new StringBuilder();
        int index = 0;
        while (index < buffer.length) {
            for (int i=0; i < 8; i++) {
                if (index >= buffer.length) {
                    break;
                }
                builder.append(String.format(Locale.getDefault(), "0x%02x", buffer[index]));
                builder.append(" ");
                index++;
            }
            builder.append("\n");
        }
        Log.d(TAG, builder.toString());
        Log.d(TAG, "[" + buffer.length + "]");
    }

    @VisibleForTesting
    public static boolean isEqualBytes(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        for (int i=0; i<a.length; i++) {
            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }
}
