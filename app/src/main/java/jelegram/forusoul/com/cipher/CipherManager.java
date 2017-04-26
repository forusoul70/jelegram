package jelegram.forusoul.com.cipher;

import android.support.compat.BuildConfig;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Manage Cipher logic
 */

public class CipherManager {
    static {
        System.loadLibrary("native-lib");
    }

    private static final String TAG = "CipherManager";
    public static final int SHA_DIGEST_LENGTH = 20;

    private byte[] mInitializeKeyBuffer = null;
    private final byte[] mEncryptionKey = new byte[32];
    private final byte[] mEncryptionIv = new byte[16];
    private final byte[] mEncryptionCounter = new byte[16];
    private final int[] mEncryptionNumber = new int[1];

    private final byte[] mDecryptionKey = new byte[32];
    private final byte[] mDecryptionIv = new byte[16];
    private final byte[] mDecryptionCounter = new byte[16];
    private final int[] mDecryptionNumber = new int[1];

    private final ConcurrentHashMap<Long, String> mServerPublicKeyMap = new ConcurrentHashMap<>();

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

        // init server public key
        mServerPublicKeyMap.put(0xc3b42b026ce86b21L, "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBCgKCAQEAwVACPi9w23mF3tBkdZz+zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6\n" +
                "lyDONS789sVoD/xCS9Y0hkkC3gtL1tSfTlgCMOOul9lcixlEKzwKENj1Yz/s7daS\n" +
                "an9tqw3bfUV/nqgbhGX81v/+7RFAEd+RwFnK7a+XYl9sluzHRyVVaTTveB2GazTw\n" +
                "Efzk2DWgkBluml8OREmvfraX3bkHZJTKX4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+\n" +
                "8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd9P0NsZRPsmoqVwMbMu7mStFai6aIhc3n\n" +
                "Slv8kg9qv1m6XHVQY3PnEw+QQtqSIXklHwIDAQAB\n" +
                "-----END RSA PUBLIC KEY-----");
        mServerPublicKeyMap.put(0x9a996a1db11c729bL, "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBCgKCAQEAxq7aeLAqJR20tkQQMfRn+ocfrtMlJsQ2Uksfs7Xcoo77jAid0bRt\n" +
                "ksiVmT2HEIJUlRxfABoPBV8wY9zRTUMaMA654pUX41mhyVN+XoerGxFvrs9dF1Ru\n" +
                "vCHbI02dM2ppPvyytvvMoefRoL5BTcpAihFgm5xCaakgsJ/tH5oVl74CdhQw8J5L\n" +
                "xI/K++KJBUyZ26Uba1632cOiq05JBUW0Z2vWIOk4BLysk7+U9z+SxynKiZR3/xdi\n" +
                "XvFKk01R3BHV+GUKM2RYazpS/P8v7eyKhAbKxOdRcFpHLlVwfjyM1VlDQrEZxsMp\n" +
                "NTLYXb6Sce1Uov0YtNx5wEowlREH1WOTlwIDAQAB\n" +
                "-----END RSA PUBLIC KEY-----");
        mServerPublicKeyMap.put(0xb05b2a6f70cdea78L, "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBCgKCAQEAsQZnSWVZNfClk29RcDTJQ76n8zZaiTGuUsi8sUhW8AS4PSbPKDm+\n" +
                "DyJgdHDWdIF3HBzl7DHeFrILuqTs0vfS7Pa2NW8nUBwiaYQmPtwEa4n7bTmBVGsB\n" +
                "1700/tz8wQWOLUlL2nMv+BPlDhxq4kmJCyJfgrIrHlX8sGPcPA4Y6Rwo0MSqYn3s\n" +
                "g1Pu5gOKlaT9HKmE6wn5Sut6IiBjWozrRQ6n5h2RXNtO7O2qCDqjgB2vBxhV7B+z\n" +
                "hRbLbCmW0tYMDsvPpX5M8fsO05svN+lKtCAuz1leFns8piZpptpSCFn7bWxiA9/f\n" +
                "x5x17D7pfah3Sy2pA+NDXyzSlGcKdaUmwQIDAQAB\n" +
                "-----END RSA PUBLIC KEY-----");
        mServerPublicKeyMap.put(0x71e025b6c76033e3L, "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIBCgKCAQEAwqjFW0pi4reKGbkc9pK83Eunwj/k0G8ZTioMMPbZmW99GivMibwa\n" +
                "xDM9RDWabEMyUtGoQC2ZcDeLWRK3W8jMP6dnEKAlvLkDLfC4fXYHzFO5KHEqF06i\n" +
                "qAqBdmI1iBGdQv/OQCBcbXIWCGDY2AsiqLhlGQfPOI7/vvKc188rTriocgUtoTUc\n" +
                "/n/sIUzkgwTqRyvWYynWARWzQg0I9olLBBC2q5RQJJlnYXZwyTL3y9tdb7zOHkks\n" +
                "WV9IMQmZmyZh/N7sMbGWQpt4NMchGpPGeJ2e5gHBjDnlIf2p1yZOYeUYrdbwcS0t\n" +
                "UiggS4UeE8TzIuXFQxw7fzEIlmhIaq3FnwIDAQAB\n" +
                "-----END RSA PUBLIC KEY-----");
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
        byte[] encryptionKeyBuffer = encryptAesMessage(initKeyBuffer);
        System.arraycopy(encryptionKeyBuffer, 56, initKeyBuffer, 56, 8);
        return initKeyBuffer;
    }

    public byte[] decryptAesIge(byte[] in, byte[] key, byte[] iv) {
        if (in == null || in.length == 0) {
            return null;
        }

        if (key == null || key.length == 0) {
            return null;
        }

        if (iv == null || iv.length == 0) {
            return null;
        }

        return native_requestDecryptAesIge(in, key, iv);
    }

    public byte[] encryptAesIge(byte[] in, byte[] key, byte[] iv) {
        if (in == null || in.length == 0) {
            return null;
        }

        if (key == null || key.length == 0) {
            return null;
        }

        if (iv == null || iv.length == 0) {
            return null;
        }

        return native_requestEncryptAesIge(in, key, iv);
    }

    public byte[] encryptAesMessage(byte[] in)
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

    public byte[] requestSha1(byte[] in) {
        if (in == null || in.length == 0) {
            return null;
        }

        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(in);
            return crypt.digest();
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "requestSha1()", e);
            }
            return null;
        }
    }

    public byte[] requestEncryptRsa(long publicKeyFingerPrint, byte[] in) {
        if (in == null || in.length == 0) {
            return null;
        }

        String publicKey = mServerPublicKeyMap.get(publicKeyFingerPrint);
        if (publicKey == null || publicKey.length() == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, String.format(Locale.getDefault(), "requestEncryptRsa(), Failed to find server public key [0x%x]", publicKeyFingerPrint));
            }
            return null;
        }

        byte[] encryptionData = native_requestRsaEncrypt(publicKey, in);
        if (encryptionData == null || encryptionData.length == 0) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "requestEncryptRsa(), Failed to encryption");
            }
            return null;
        }

        return encryptionData;
    }

    public ArrayList<byte[]> requestCalculateDiffieHellmanGB(byte[] prime, int g, final byte[] ga) {
        if (prime == null || prime.length == 0) {
            return null;
        }

        if (g <= 0) {
            return null;
        }

        if (ga == null || ga.length == 0) {
            return null;
        }

        final ArrayList<byte[]> calculateResult = new ArrayList<>();
        final CountDownLatch waitCallbackLatch = new CountDownLatch(1);
        native_requestCalculateDiffieHellmanGB(prime, g, ga, new CalculateDiffieHellmanGBCallback() {
            @Override
            public void onFinished(byte[] b, byte[] gb) {
                if (b != null && b.length > 0 && gb != null && gb.length > 0) {
                    calculateResult.add(b);
                    calculateResult.add(gb);
                }
                waitCallbackLatch.countDown();
            }
        });
        try {
            waitCallbackLatch.await(1, TimeUnit.MINUTES);
        } catch (InterruptedException ignore) {

        }

        return calculateResult;
    }

    public byte[] requestCalculateModExp(byte[] in, byte[] prime, byte[] m) {
        if (in == null || in.length == 0) {
            return null;
        }

        if (prime == null || prime.length == 0) {
            return null;
        }

        if (m == null || m.length == 0) {
            return null;
        }

        return native_requestCalculateModExp(in, prime, m);
    }


    public static int[] factorizePQ(byte[] pqValue) {
        return native_requestFactorizePQ(pqValue);
    }

    private static native void native_requestAesCtrEncrypt(byte[] in, byte[] out, int length, byte[] encryptionKey, byte[] initializeVector, byte[] counterBuffer, int[] number);

    private static native byte[] native_requestRsaEncrypt(String publicKey, byte[] in);

    private static native int[] native_requestFactorizePQ(byte[] pqValue);

    private static native byte[] native_requestDecryptAesIge(byte[] in, byte[] key, byte[] iv);

    private static native byte[] native_requestEncryptAesIge(byte[] in, byte[] key, byte[] iv);

    private interface CalculateDiffieHellmanGBCallback {
        void onFinished(byte[] b, byte[] gb);
    }

    private static native void native_requestCalculateDiffieHellmanGB(byte[] prime, int g, byte[] ga, CalculateDiffieHellmanGBCallback callback);

    private static native byte[] native_requestCalculateModExp(byte[] in, byte[] prime, byte[] mod);
}
