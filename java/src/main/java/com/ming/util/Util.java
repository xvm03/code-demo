package com.ming.util;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Random;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 *
 * <p>Title: Util</p>
 * <p>Description: Java加密解密公共方法</p>
 * @author Dumbbell Yang
 * @Date   2010-01-11
 * @version 1.0
 */

public class Util {

    //測試用于加密解密的文件
    public final static String[] TEST_FILES = new String[]{
            "C:\\xml\\391Sample.xml",
            "C:\\xml\\2134Sample.xml",
            "C:\\xml\\4876Sample.xml",
            "C:\\xml\\8381Sample.xml",
            "C:\\xml\\12571Sample.xml"
    };

    //測試用于加密解密的文件 for Android
    public final static String[] TEST_FILES_ANDROID = new String[]{
            "C:\\xml\\391Sample.xml",
            "C:\\xml\\375Sample.xml",
            "C:\\xml\\353Sample.xml"
    };

    public final static String[] ENCRYPTED_FILES = new String[]{
            "C:\\xml\\Enc391Sample.xml",
            "C:\\xml\\Enc2134Sample.xml",
            "C:\\xml\\Enc4876Sample.xml",
            "C:\\xml\\Enc8381Sample.xml",
            "C:\\xml\\Enc12571Sample.xml"
    };

    public final static String[] DECRYPTED_FILES = new String[]{
            "C:\\xml\\Dec391Sample.xml",
            "C:\\xml\\Dec2134Sample.xml",
            "C:\\xml\\Dec4876Sample.xml",
            "C:\\xml\\Dec8381Sample.xml",
            "C:\\xml\\Dec12571Sample.xml"
    };

    public final static String ZIP_FOLDER = "C:\\zip\\";
    public final static String ZIP_FOLDER2 = "C:\\zip2\\";
    public final static String ZIP_FOLDER3 = "C:\\zip3\\";
    public final static String ZIP_TO_FILE = "C:\\sales_data.zip";
    public final static String ZIP_TO_FILE_NAME = "C:\\sales_data_";
    public final static String ZIP_TO_FILE_EXT = ".zip";
    public final static String UNZIP_TO_FOLDER = "C:\\unzip\\";
    public final static String SYMMETRIC_KEY_FILE = "symmetric.key";

    //測試用于加密解密的字符串
    public final static String[] TEST_STRING = new String[]{
            "15257100971"
    };

    public static String getFileName(String strFilePath){
        return strFilePath.substring(strFilePath.lastIndexOf("\\") + 1);
    }

    //字串寫入二進制文件
    public static void saveToFile(String strString,String strFile) {
        try {
            FileOutputStream file = new FileOutputStream(strFile);
            file.write(strString.getBytes());
            file.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    //測試用OC生成的RSA Public Key字符串
    public static final String OC_RSA_PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYO1yULWFbBF8DxC9Rw4"
                    + "AFg88Ft0EpgcSN4O9SWzXi5ktGUA2ZYp2HdKaWe/qV7G9fJU1W1vkueABtuy3zKe"
                    + "u2zbAzCd0d3hQtfxDlwEkU2AfxXXRnm8Oyv4EoWAqEe8d/EE7ocSotx+yLBsI2vr"
                    + "XddQrnVbpIKgvsPyewNVG0ppuRqQifNPQpAW3lmOUmz7j74qCV66zEgP5Ikvb4Dc"
                    + "nZN+iu9KUKWOvwU90Sg/XHknBvBkVnm4l1NnWJ7MRR5qvFud0k883CrBHSHA9i0O"
                    + "C1NDMwveI5MXWNK/0UB9kE+cq6aXWus8YCAOuCxz88cyY1P3fiVfSco11wpuZLTL"
                    + "pQIDAQAB";

    //測試用Android生成的RSA Public Key字符串
    public static final String ANDROID_RSA_PUBLIC_KEY =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv0mQn/+d9miop0tgjBl5"
                    + "kIOVRBLXbi1M8K0X4/fK/UqqGyFfWifdUA6C3k4lXbtXrGaYhWjr6PisVqQNp9wI"
                    + "EwAzFOHWmZjt3XFfD5ENtBvFYSdXM3aICoGy9vM01bPPXaHVydA41fD9EAmipuWO"
                    + "ZtjXlATH3M1ROvM5w0z33JPnqBn92sIt/U2PoNdEOqWhsGimrmpfaZzscAcUNN1H"
                    + "HJaWt2oksrBuDHOZ5eBidrvkRPTAcWJ6108LDgpBYsYA0URkQ0F/sia2lmyv+rK3"
                    + "RSSTHrP8zaodVyP463p4RvVKdTKYac6XtzhVWSagteZPxF2vY1b77tZM/BhmsMUQ"
                    + "PwIDAQAB";

    //根據指定字符集生成隨機字符串
    private static final String charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/";
    public static String getRandomString(int length) {
        Random rand = new Random(System.currentTimeMillis());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int pos = rand.nextInt(charset.length());
            sb.append(charset.charAt(pos));
        }
        return sb.toString();
    }

    //從UUID生成隨機字符串
    public static String getRandomUUID(int length) {
        String strUUID = UUID.randomUUID().toString();
        System.out.println("UUID length:" + strUUID.length());
        while(strUUID.length() < length){
            strUUID += UUID.randomUUID().toString();
        }

        return strUUID.substring(0, length);
    }

    //剔除文本中的換行符
    public static String replaceNewLine(String strText){
        String strResult = "";
        int intStart = 0;
        int intLoc = strText.indexOf("\n", intStart);
        while(intLoc != -1){
            strResult += strText.substring(intStart, intLoc - 1);
            intStart = intLoc + 1;
            intLoc = strText.indexOf("\n", intStart);
        }
        strResult += strText.substring(intStart,strText.length());
        return strResult;
    }

    //字節到十六進制串轉換
    public static String byte2hex(byte[] b){
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n ++){
            stmp = Integer.toHexString(b[n] & 0xFF);
            if (stmp.length() == 1)
                hs += ("0" + stmp);
            else
                hs += stmp;
        }
        return hs.toUpperCase();
    }

    //十六進制串到字節轉換
    public static byte[] hex2byte(byte[] b){
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数!");

        byte[] b2 = new byte[b.length / 2];

        for (int n = 0; n < b.length; n += 2){
            String item = new String(b, n, 2);
            b2[n/2] = (byte)Integer.parseInt(item, 16);
        }
        return b2;
    }

    public static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
        }
        return result;
    }

    public static byte[] Base64Encode(byte[] bytes)
            throws UnsupportedEncodingException{
        BASE64Encoder base64encoder = new BASE64Encoder();
        String encode = base64encoder.encode(bytes);

        return encode.getBytes();
    }

    public static byte[] Base64Decode(byte[] bytes)
            throws IOException{
        BASE64Decoder base64decoder = new BASE64Decoder();
        return base64decoder.decodeBuffer(new String(bytes));
    }

    public static String getCurrentDateTime(){
        SimpleDateFormat sDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        return sDateFormat.format(new java.util.Date());
    }

    public static String getCurrentDateTimeString(){
        SimpleDateFormat sDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
        return sDateFormat.format(new java.util.Date());
    }

    private static String zipFiles(String[] files, String zipToFile){
        // Create a buffer for reading the files
        byte[] buf = new byte[1024];
        File file = new File(zipToFile);
        if (file.exists()){
            file.delete();
        }

        try {
            ZipOutputStream out = new ZipOutputStream(new FileOutputStream(zipToFile));

            // Compress the files
            for (int i=0; i< files.length; i++) {
                if (new File(files[i]).exists()){
                    FileInputStream in = new FileInputStream(files[i]);

                    // Add ZIP entry to output stream.
                    out.putNextEntry(new ZipEntry(getFileName(files[i])));

                    // Transfer bytes from the file to the ZIP file
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }

                    // Complete the entry
                    out.closeEntry();
                    in.close();
                }
            }

            // Complete the ZIP file
            out.close();

            return zipToFile;
        }
        catch (IOException e) {
            System.out.println(e.toString());

            return "";
        }
    }

    private static String zipFolder(String strFolder,String zipToFile){
        File folder = new File(strFolder);

        if (folder.isDirectory()){
            File[] files = folder.listFiles();
            String[] arrFiles = new String[files.length];
            for(int i = 0;i < files.length;i ++){
                arrFiles[i] = files[i].getAbsolutePath();
            }
            return zipFiles(arrFiles,zipToFile);
        }
        else{
            return zipFiles(new String[]{strFolder},zipToFile);
        }
    }

    public static String unzipFile(String zippedFile, String unzipToFolder){
        if (new File(zippedFile).exists()){
            try {
                InputStream in = new BufferedInputStream(new FileInputStream(zippedFile));
                ZipInputStream zin = new ZipInputStream(in);

                File file = new File(unzipToFolder);
                if (file.exists() == false){
                    file.mkdirs();
                }

                ZipEntry e;
                while((e = zin.getNextEntry())!= null) {
                    String s = e.getName();
                    File f = new File(unzipToFolder, s);

                    FileOutputStream out = new FileOutputStream(f);
                    byte [] b = new byte[512];
                    int len = 0;
                    while ((len = zin.read(b))!= -1 ) {
                        out.write(b,0,len);
                    }
                    out.close();
                }
                zin.close();

                return unzipToFolder;
            }
            catch (IOException e) {
                System.out.println(e.toString());

                return "";
            }
        }
        else{
            return "";
        }
    }

    static byte[] generateMd5(String keyb){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
       return  md.digest(keyb.getBytes());

    }
    static SecretKeySpec generateKey(String jsKey){

        byte[] keyb = new byte[24];
        try {
            keyb = jsKey.getBytes("utf-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] thedigest = md.digest(keyb);

        byte[] keyb2 = new byte[24];

        System.out.println(thedigest.length);
//        for(int i=0;i<thedigest.length;i++){
//            keyb2[i]=thedigest[i];
//
//        }
//        for(int i=16;i<keyb2.length;i++){
//
//            keyb2[i]=thedigest[i-16];
//        }
//        System.out.println(keyb2.length);

        SecretKeySpec skey = new SecretKeySpec(thedigest, "AES");

        return skey;
    }

    static SecretKeySpec generate192(){

        KeyGenerator kgen = null;
        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        kgen.init(128, new SecureRandom("cheniu_2014".getBytes()));
        SecretKey secretKey = kgen.generateKey();
        byte[] enCodeFormat = secretKey.getEncoded();
        return new SecretKeySpec(enCodeFormat, "AES");
    }
//    //測試全部功能：
//    //1. 從OC接收RSA 公鑰
//    //2. 生成DES 3DES (AES128 AES256 暫時不能對文件加密 ) 對稱密鑰
//    //3. 用對稱密鑰對數據文件加密
//    //4. 用RSA公鑰對對稱密鑰加密，并存為密鑰文件
//    //5. 壓縮加密的數據文件和密鑰文件，傳給OC
//    //6. OC解壓縮出數據文件和密鑰文件
//    //7. OC用自己的私鑰解密密鑰文件，得到對稱密鑰
//    //8. OC用解出的對稱密鑰解密數據文件。
//    //DES加密
//    public static void testDESAllFunction(String strOCPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //OC RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strOCPublicKey);
//
//        //生成一個隨機字符串，作為DES key
//        String strRandomString = getRandomString(8);
//        System.out.println(strRandomString);
//        DESCrypto.DESKeySpec = DESCrypto.getDESKeySpecFromString(strRandomString);
//        System.out.println(DESCrypto.getDESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER).exists() == false){
//            new File(ZIP_FOLDER).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES.length;i ++){
//            String strCurFile = TEST_FILES[i];
//            String encryptedFile = ZIP_FOLDER + "Enc" + getFileName(strCurFile);
//            DESCrypto.encryptFile(new File(strCurFile), encryptedFile, false);
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(DESCrypto.getDESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    //測試全部功能：
//    //1. 從OC接收RSA 公鑰
//    //2. 生成DES 3DES (AES128 AES256 暫時不能對文件加密 ) 對稱密鑰
//    //3. 用對稱密鑰對數據文件加密
//    //4. 用RSA公鑰對對稱密鑰加密，并存為密鑰文件
//    //5. 壓縮加密的數據文件和密鑰文件，傳給OC
//    //6. OC解壓縮出數據文件和密鑰文件
//    //7. OC用自己的私鑰解密密鑰文件，得到對稱密鑰
//    //8. OC用解出的對稱密鑰解密數據文件。
//    //DES加密
//    public static void testDESAllFunctionForAndroid(String strAndroidPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //Android RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strAndroidPublicKey);
//
//        //生成一個隨機字符串，作為DES key
//        String strRandomString = getRandomString(8);
//        System.out.println(strRandomString);
//        DESCrypto.DESKeySpec = DESCrypto.getDESKeySpecFromString(strRandomString);
//        //System.out.println(DESCrypto.getDESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER).exists() == false){
//            new File(ZIP_FOLDER).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES_ANDROID.length;i ++){
//            String strCurFile = TEST_FILES_ANDROID[i];
//            String encryptedFile = ZIP_FOLDER + "Enc" + getFileName(strCurFile);
//            DESCrypto.encryptFile(new File(strCurFile), encryptedFile, false);
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(DESCrypto.getDESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    //3DES加密
//    public static void test3DESAllFunction(String strOCPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //OC RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strOCPublicKey);
//
//        //生成一個隨機字符串，作為DES key
//        String strRandomString = getRandomString(24);
//        System.out.println(strRandomString);
//        DESCrypto.tripleDESKeySpec = DESCrypto.getTripleDESKeySpecFromString(strRandomString);
//        //System.out.println(DESCrypto.getTripleDESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER2).exists() == false){
//            new File(ZIP_FOLDER2).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES.length;i ++){
//            String strCurFile = TEST_FILES[i];
//            String encryptedFile = ZIP_FOLDER2 + "Enc" + getFileName(strCurFile);
//            DESCrypto.encryptFile(new File(strCurFile), encryptedFile, true);
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(DESCrypto.getTripleDESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER2 + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER2,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    //3DES加密 for Android
//    public static void test3DESAllFunctionForAndroid(String strAndroidPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //Android RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strAndroidPublicKey);
//
//        //生成一個隨機字符串，作為DES key
//        String strRandomString = getRandomString(24);
//        System.out.println(strRandomString);
//        DESCrypto.tripleDESKeySpec = DESCrypto.getTripleDESKeySpecFromString(strRandomString);
//        //System.out.println(DESCrypto.getTripleDESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER2).exists() == false){
//            new File(ZIP_FOLDER2).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES_ANDROID.length;i ++){
//            String strCurFile = TEST_FILES_ANDROID[i];
//            String encryptedFile = ZIP_FOLDER2 + "Enc" + getFileName(strCurFile);
//            DESCrypto.encryptFile(new File(strCurFile), encryptedFile, true);
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(DESCrypto.getTripleDESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER2 + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER2,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    public static void testAES128AllFunction(String strOCPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //OC RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strOCPublicKey);
//
//        //生成一個隨機字符串，作為AES128 key
//        String strRandomString = getRandomString(16);
//        System.out.println(strRandomString);
//        AESCrypto.AESKeySpec = AESCrypto.getAESKeySpecFromString(strRandomString);
//        //System.out.println(AESCrypto.getAESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER3).exists() == false){
//            new File(ZIP_FOLDER3).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES.length;i ++){
//            String strCurFile = TEST_FILES[i];
//            String encryptedFile = ZIP_FOLDER3 + "Enc" + getFileName(strCurFile);
//            AESCrypto.encryptFile(new File(strCurFile), new File(encryptedFile));
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(AESCrypto.getAESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER3 + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER3,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    public static void testAES128AllFunctionForAndroid(String strAndroidPublicKey) throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //Android RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strAndroidPublicKey);
//
//        //生成一個隨機字符串，作為AES128 key
//        String strRandomString = getRandomString(16);
//        System.out.println(strRandomString);
//        AESCrypto.AESKeySpec = AESCrypto.getAESKeySpecFromString(strRandomString);
//        //System.out.println(AESCrypto.getAESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER3).exists() == false){
//            new File(ZIP_FOLDER3).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES_ANDROID.length;i ++){
//            String strCurFile = TEST_FILES_ANDROID[i];
//            String encryptedFile = ZIP_FOLDER3 + "Enc" + getFileName(strCurFile);
//            AESCrypto.encryptFile(new File(strCurFile), new File(encryptedFile));
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(AESCrypto.getAESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER3 + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER3,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }
//
//    //因為Objective C 用AES 256 算法無法解密Java AES 256算法加密的密文，故此方法未實現
//    public static void testAES256AllFunction(){
//
//    }
//
//    public static void testAES256AllFunctionForAndroid(String strAndroidPublicKey)
//            throws Exception{
//        System.out.println("Start:" + getCurrentDateTime());
//        //Android RSA Public Key
//        RSACrypto.uk = (RSAPublicKey) RSACrypto.getPublicKeyFromString(strAndroidPublicKey);
//
//        //生成一個隨機字符串，作為AES 256 key
//        String strRandomString = getRandomString(32);
//        System.out.println(strRandomString);
//        AESCrypto.AESKeySpec = AESCrypto.getAESKeySpecFromString(strRandomString);
//        //System.out.println(AESCrypto.getAESKeyString());
//
//        //檢查文件夾是否存在，如果不存在，創建
//        if (new File(ZIP_FOLDER3).exists() == false){
//            new File(ZIP_FOLDER3).mkdir();
//        }
//
//        //壓縮數據文件
//        for(int i = 0;i < TEST_FILES_ANDROID.length;i ++){
//            String strCurFile = TEST_FILES_ANDROID[i];
//            String encryptedFile = ZIP_FOLDER3 + "Enc" + getFileName(strCurFile);
//            AESCrypto.encryptFile(new File(strCurFile), new File(encryptedFile));
//        }
//
//        //對DES key進行RSA加密
//        String strEncryptedKey = RSACrypto.encrypt(AESCrypto.getAESKeyString());
//        //System.out.println(strEncryptedKey);
//
//        //加密的DES key寫入文件
//        saveToFile(strEncryptedKey,ZIP_FOLDER3 + SYMMETRIC_KEY_FILE);
//
//        //壓縮加密的數據文件和加密的DES key文件
//        String strZipToFile = zipFolder(ZIP_FOLDER3,ZIP_TO_FILE_NAME + getCurrentDateTimeString() + ZIP_TO_FILE_EXT);
//        System.out.println("Zip to File:" + strZipToFile);
//
//        System.out.println("End:" + getCurrentDateTime());
//    }

    public static String a(){

        throw  new RuntimeException(("test"));
    }

    public static String b(){
        a();
        return "b";
    }

    public static void main(String args[]){

        b();

//
//        //-XX:AutoBoxCacheMax=11
//        Integer a = 300;
//        Integer b =300;
//        if(a==b){
//            System.out.println(true);
//        }
//
//        System.out.println(Integer.valueOf(10));;

        //zipFiles(TEST_FILES,ZIP_TO_FILE);
        //System.out.println(unzipFile(ZIP_TO_FILE,UNZIP_TO_FOLDER));
        try {
            //testDESAllFunction(OC_RSA_PUBLIC_KEY);
            //test3DESAllFunction(OC_RSA_PUBLIC_KEY);
            //testAES128AllFunction(OC_RSA_PUBLIC_KEY);
            //testAES256AllFunction();
            //testDESAllFunctionForAndroid(ANDROID_RSA_PUBLIC_KEY);
            //test3DESAllFunctionForAndroid(ANDROID_RSA_PUBLIC_KEY);
            //testAES128AllFunctionForAndroid(ANDROID_RSA_PUBLIC_KEY);
            //testAES256AllFunctionForAndroid(ANDROID_RSA_PUBLIC_KEY);
        }
        catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}