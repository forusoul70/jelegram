package jelegram.forusoul.com.cipher;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Manage Cipher logic
 */

public class CipherManager {
    private static final String TAG = "CipherManager";
    private byte[] mInitializeKeyBuffer = null;
    private final byte[] mEncryptionKey = new byte[32];
    private final byte[] mEncryptionIv = new byte[16];
    private final byte[] mEncryptionCounter = new byte[16];
    private final int[] mEncryptionNumber = new int[1];

    private final byte[] mDecryptionKey = new byte[32];
    private final byte[] mDecryptionIv = new byte[16];
    private final byte[] mDecryptionCounter = new byte[16];
    private final int[] mDecryptionNumber = new int[1];


    private static class SingletonHolder {
        static final CipherManager INSTANCE = new CipherManager();
    }

    public static CipherManager getInstance() {
        return CipherManager.SingletonHolder.INSTANCE;
    }
    private CipherManager() {
        initialize();
    }

    private void initialize() {
        // Initialize key
        for (;;) {
            SecureRandom secureRandom = new SecureRandom();
            mInitializeKeyBuffer = secureRandom.generateSeed(64);

            int value = (mInitializeKeyBuffer[3] << 24) | (mInitializeKeyBuffer[2] << 16) | (mInitializeKeyBuffer[1] << 8) | (mInitializeKeyBuffer[0]);
            int value2 = (mInitializeKeyBuffer[7] << 24) | (mInitializeKeyBuffer[6] << 16) | (mInitializeKeyBuffer[5] << 8) | (mInitializeKeyBuffer[4]);
            if (mInitializeKeyBuffer[0] != ((byte)0xef) && value != 0x44414548 && value != 0x54534f50 &&
                    value != 0x20544547 && value != 0x4954504f && value != 0xeeeeeeee && value2 != 0x00000000) {
                mInitializeKeyBuffer[56] = mInitializeKeyBuffer[57] = mInitializeKeyBuffer[58] = mInitializeKeyBuffer[59] = (byte) 0xef;
                break;
            }
        }

        // setting key
        Arrays.fill(mEncryptionKey, (byte) 0);
        Arrays.fill(mEncryptionIv, (byte) 0);
        Arrays.fill(mEncryptionCounter, (byte) 0);
        mEncryptionNumber[0] = 0;
        System.arraycopy(mInitializeKeyBuffer, 8, mEncryptionKey, 0, 32);
        System.arraycopy(mInitializeKeyBuffer, 40, mEncryptionIv, 0, 16);

        byte[] decryptionBuffer = new byte[64];
        for (int i = 0; i < 48; i++) {
            decryptionBuffer[i] = mInitializeKeyBuffer[55 -i];
        }

        Arrays.fill(mDecryptionKey, (byte) 0);
        Arrays.fill(mDecryptionIv, (byte) 0);
        Arrays.fill(mDecryptionCounter, (byte) 0);
        mDecryptionNumber[0] = 0;
        System.arraycopy(decryptionBuffer, 0, mDecryptionKey, 0, 32);
        System.arraycopy(decryptionBuffer, 32, mDecryptionIv, 0, 16);
    }

    public byte[] getInitializeKeyReportData()
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
        if (mInitializeKeyBuffer == null) {
            return null;
        }

        // clone
        byte[] initKeyBuffer = new byte[mInitializeKeyBuffer.length];
        System.arraycopy(mInitializeKeyBuffer, 0, initKeyBuffer, 0, mInitializeKeyBuffer.length);

        // encrypt
        byte[] encryptionKeyBuffer = encryptAesCtrModeNoPadding(initKeyBuffer);
        System.arraycopy(encryptionKeyBuffer, 56, initKeyBuffer, 56, 8);
        return initKeyBuffer;
    }

    public byte[] encryptAesCtrModeNoPadding(byte[] in)
            throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

        if (in == null || in.length == 0) {
            return null;
        }

        final int length = in.length;
        byte[] out = new byte[length];
        native_requestAesCtrEncrypt(in, out, length, mEncryptionKey, mEncryptionIv, mEncryptionCounter, mEncryptionNumber);
        return out;
    }

    public byte[] decryptAesCtrModeNoPadding(byte[] in) {
        if (in == null || in.length == 0) {
            return null;
        }

        final int length = in.length;
        byte[] out = new byte[length];
        native_requestAesCtrEncrypt(in, out, length, mDecryptionKey, mDecryptionIv, mDecryptionCounter, mDecryptionNumber);
        return out;
    }

    public static native void native_requestAesCtrEncrypt(byte[] in, byte[] out, int length, byte[] encryptionKey, byte[] initializeVector, byte[] counterBuffer, int[] number);

}
