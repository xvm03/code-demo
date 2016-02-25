package com.ming;

import com.ming.util.Util;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * 对应nodejs的aes加解密
 *
 * xumingming 16/2/24.
 */
public class OpenSSLDecryptor {

    private static final int INDEX_KEY = 0;
    private static final int INDEX_IV = 1;
    private static final int ITERATIONS = 1;

    private static final int KEY_SIZE_BITS = 192;

    /**
     * Thanks go to Ola Bini for releasing this source on his blog. The source was obtained from <a
     * href="http://olabini.com/blog/tag/evp_bytestokey/">here</a> .
     */
    public static byte[][] EVP_BytesToKey(int key_len, int iv_len, MessageDigest md, byte[] salt, byte[] data, int count) {
        byte[][] both = new byte[2][];
        byte[] key = new byte[key_len];
        int key_ix = 0;
        byte[] iv = new byte[iv_len];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (;;) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            if (null != salt) {
                md.update(salt, 0, 8);
            }
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (;;) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (;;) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }

    public static byte[] encrypt(byte[] salt, byte[] contents, String pw) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        final byte[][] keyAndIV = EVP_BytesToKey(KEY_SIZE_BITS / Byte.SIZE, aesCBC.getBlockSize(), md5, salt, pw.getBytes(), ITERATIONS);
        SecretKeySpec key = new SecretKeySpec(keyAndIV[INDEX_KEY], "AES");
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[INDEX_IV]);

        aesCBC.init(Cipher.ENCRYPT_MODE, key, iv);
        return aesCBC.doFinal(contents);
    }

    public static byte[] decrypt(byte[] salt, byte[] encrypted, String pw) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        final byte[][] keyAndIV = EVP_BytesToKey(KEY_SIZE_BITS / Byte.SIZE, aesCBC.getBlockSize(), md5, salt, pw.getBytes(), ITERATIONS);
        SecretKeySpec key = new SecretKeySpec(keyAndIV[INDEX_KEY], "AES");
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[INDEX_IV]);

        aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
        return aesCBC.doFinal(encrypted);
    }


    //

    /**
     * nodejs 加密，secret是用来生成key 和iv 调用的是openSSL的EVP_BytesToKey
     *
     * EVP_BytesToKey填充的/0，java没有，于是牛人出现了，自己实现了一个
    *g
     * exports.encrypt = function (str) {
     * var cipher = crypto.createCipher('aes192', secret);
     * var enc = cipher.update(str, 'utf8', 'hex');
     * enc += cipher.final('hex');
     * return enc;
     * };
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        String pw = "password2016";

        byte[] salt = null;
        byte[] encrypted = "15257100971".getBytes();

        byte[] decrypted = encrypt(salt, encrypted, pw);
        System.out.println(Util.byte2hex(decrypted));

        BASE64Encoder base64Encoder = new BASE64Encoder();
        String str = base64Encoder.encode(decrypted);
        System.out.println(str);
        String answer = new String(decrypt(salt, decrypted, pw));
        System.out.println(answer);

        BASE64Decoder base64Decoder = new BASE64Decoder();

        answer = new String(decrypt(salt, base64Decoder.decodeBuffer(str), pw));
        System.out.println(answer);
    }

}
