package jelegram.forusoul.com.protocol;

import android.support.annotation.NonNull;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.cipher.CipherManager;
import jelegram.forusoul.com.utils.ByteUtils;

/**
 * Response of DH param
 */

public class ResDHParam implements IProtocol {

    public class DHParamException extends Exception {
        private final String message;

        private DHParamException(String message) {
            super();
            this.message = message;
        }
    }

    private static final String TAG = "ResDHParam";

    private final byte[] mNewNonce = new byte[32];
    private final byte[] mClientNonce = new byte[16];
    private final byte[] mServerNonce = new byte[16];

    private byte[] mDecryptionKey = null;
    private byte[] mDecryptionIV = null;
    private byte[] mDecryptedAnswer = null;

    private ResDHInnerData mInnerData = null;

    public ResDHParam(byte[] newNonce) throws DHParamException {
        if (newNonce == null || newNonce.length != 32) {
            throw new DHParamException("Invalid new nonce length");
        }

        System.arraycopy(newNonce, 0, mNewNonce, 0, 32);
    }

    @Override
    public int getConstructor() {
        return 0xd0e8075c;
    }

    @Override
    public boolean isHandshakeProtocol() {
        return true;
    }

    @Override
    public byte[] serializeSteam() {
        return null;
    }

    @Override
    public void readFromStream(@NonNull InputStream stream, int length) throws DHParamException {
        try {
            int rc = stream.read(mClientNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read nonce [" + rc + "]");
                }
                return;
            }

            rc = stream.read(mServerNonce);
            if (rc != 16) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read server nonce [" + rc + "]");
                }
                return;
            }

            byte[] encryptedAnswer = ByteUtils.readByteArray(stream);
            if (encryptedAnswer == null || encryptedAnswer.length == 0) {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, "readFromStream(), Failed to read encrypted answer");
                }
                return;
            }

            ByteArrayOutputStream aseKeyAndIv = new ByteArrayOutputStream();
            byte[] shaResult;

            ByteArrayOutputStream newNonceAndServerNonce = new ByteArrayOutputStream();
            newNonceAndServerNonce.write(mNewNonce);
            newNonceAndServerNonce.write(mServerNonce);
            shaResult = CipherManager.getInstance().requestSha1(newNonceAndServerNonce.toByteArray());
            if (shaResult == null || shaResult.length == 0) {
                throw new DHParamException("Failed sha with new and server nonce");
            }
            aseKeyAndIv.write(shaResult);

            ByteArrayOutputStream serverNonceAndNewNonce = new ByteArrayOutputStream();
            serverNonceAndNewNonce.write(mServerNonce);
            serverNonceAndNewNonce.write(mNewNonce);
            shaResult = CipherManager.getInstance().requestSha1(serverNonceAndNewNonce.toByteArray());
            if (shaResult == null || shaResult.length == 0) {
                throw new DHParamException("Failed sha with new and server nonce");
            }
            aseKeyAndIv.write(shaResult);

            ByteArrayOutputStream newNonceAndNewNonce = new ByteArrayOutputStream();
            newNonceAndNewNonce.write(mNewNonce);
            newNonceAndNewNonce.write(mNewNonce);
            shaResult = CipherManager.getInstance().requestSha1(newNonceAndNewNonce.toByteArray());
            if (shaResult == null || shaResult.length == 0) {
                throw new DHParamException("Failed sha with new and server nonce");
            }
            aseKeyAndIv.write(shaResult);
            aseKeyAndIv.write(mNewNonce, 0, 4);

            byte[] aseKeyAndIvBuffer = aseKeyAndIv.toByteArray();
            mDecryptionKey = Arrays.copyOfRange(aseKeyAndIvBuffer, 0, 32);
            mDecryptionIV = Arrays.copyOfRange(aseKeyAndIvBuffer, 32, 64);
            mDecryptedAnswer =  CipherManager.getInstance().decryptAesIge(encryptedAnswer, mDecryptionKey, mDecryptionIV);
            if (mDecryptedAnswer == null || mDecryptedAnswer.length == 0) {
                throw new DHParamException("Failed decrypt answer");
            }

            // verify server
            boolean hashVerify = false;
            for (int i=0; i<16; i++) {
                byte[] digest = Arrays.copyOfRange(mDecryptedAnswer, CipherManager.SHA_DIGEST_LENGTH, mDecryptedAnswer.length - i);
                shaResult = CipherManager.getInstance().requestSha1(digest);
                if (ByteUtils.isEqualBytes(shaResult, mDecryptedAnswer, CipherManager.SHA_DIGEST_LENGTH) == false) {
                    hashVerify = true;
                    break;
                }
            }

            if (hashVerify == false) {
                throw new DHParamException("Can't not decode DH params");
            }

            ByteArrayInputStream innerStream = new ByteArrayInputStream(mDecryptedAnswer);
            if (innerStream.skip(CipherManager.SHA_DIGEST_LENGTH) != CipherManager.SHA_DIGEST_LENGTH) {  // skip SHA1 hash
                return;
            }

            int innerConstructor = ByteUtils.readInt32(innerStream);
            if (innerConstructor != Constructor.ResDHInner.getConstructor()) {
                throw new DHParamException("Can't parse magic DH inner data [" + innerConstructor + "]");
            }

            mInnerData = new ResDHInnerData();
            mInnerData.readFromStream(innerStream, innerStream.available());
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "readFromStream()", e);
            }
        }
    }


    public byte[] getClientNonce() {
        return mClientNonce;
    }

    public byte[] getServerNonce() {
        return mServerNonce;
    }

    public byte[] getDHPrime() {
        return mInnerData == null ? null : mInnerData.getDHPrime();
    }

    public byte[] getGA() {
        return mInnerData == null ? null : mInnerData.getGA();
    }

    public int getG() {
        return mInnerData == null ? -1 : mInnerData.getG();
    }

    public byte[] getDecryptionKey() {
        return mDecryptionKey;
    }

    public byte[] getDecryptionIV() {
        return mDecryptionIV;
    }

    public long getServerTime() {
        return mInnerData == null ? 0 : mInnerData.getServerTime();
    }
}
