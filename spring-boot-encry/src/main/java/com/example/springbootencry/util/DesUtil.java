package com.example.springbootencry.util;

import com.alibaba.fastjson.JSON;
//import sun.misc.BASE64Decoder;
//import sun.misc.BASE64Encoder;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * DES加密 解密算法
 *
 * @author Java碎碎念
 * @date 2015-3-17 上午10:12:11
 */
public class DesUtil {

    private final static String DES = "DES";
    private final static String ENCODE = "GBK";
    private final static String defaultKey = "test12341234";

    public static void main(String[] args) throws Exception {
        Map<String, Object> map = new HashMap<>(2);
        map.put("name", "Java碎碎念");
        map.put("des", "请求参数");
        String data = "";
        System.out.println(encrypt(JSON.toJSONString(map)));

    }

    /**
     * 使用 默认key 加密
     *
     * @return String
     * @date 2015-3-17 下午02:46:43
     * // BASE64Encoder encoder = new BASE64Encoder();
     * // String encode = encoder.encode(data);
     * // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Encoder
     * Encoder encoder = Base64.getEncoder();
     * String encode = encoder.encodeToString(data);
     */
    public static String encrypt(String data) throws Exception {
        byte[] bt = encrypt(data.getBytes(ENCODE), defaultKey.getBytes(ENCODE));
//        String strs = new BASE64().encode(bt);
        Encoder encoder = Base64.getEncoder();
        String strs = encoder.encodeToString(bt);
        return strs;
    }

    /**
     * 使用 默认key 解密
     *
     * @return String
     * @date 2015-3-17 下午02:49:52
     * // BASE64Decoder decoder = new BASE64Decoder();
     * // byte[] buffer = decoder.decodeBuffer(data);
     * // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Decoder
     * Decoder decoder = Base64.getDecoder();
     * byte[] buffer = decoder.decode(data);
     */
    public static String decrypt(String data) throws IOException, Exception {
        if (data == null)
            return null;
        Decoder decoder = Base64.getDecoder();
        byte[] buf = decoder.decode(data);
        byte[] bt = decrypt(buf, defaultKey.getBytes(ENCODE));
        return new String(bt, ENCODE);
    }

    /**
     * Description 根据键值进行加密
     *
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    public static String encrypt(String data, String key) throws Exception {
        byte[] bt = encrypt(data.getBytes(ENCODE), defaultKey.getBytes(ENCODE));
//        String strs = new BASE64Encoder().encode(bt);
        Encoder encoder = Base64.getEncoder();
        String strs = encoder.encodeToString(bt);
        return strs;
    }

    /**
     * Description 根据键值进行解密
     *
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws IOException
     * @throws Exception
     */
    public static String decrypt(String data, String key) throws IOException,
            Exception {
        if (data == null)
            return null;
//        BASE64Decoder decoder = new BASE64Decoder();
//        byte[] buf = decoder.decodeBuffer(data);
        Decoder decoder = Base64.getDecoder();
        byte[] buf = decoder.decode(data);
        byte[] bt = decrypt(buf, key.getBytes(ENCODE));
        return new String(bt, ENCODE);
    }

    /**
     * Description 根据键值进行加密
     *
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);

        return cipher.doFinal(data);
    }

    /**
     * Description 根据键值进行解密
     *
     * @param data
     * @param key  加密键byte数组
     * @return
     * @throws Exception
     */
    private static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        // 生成一个可信任的随机数源
        SecureRandom sr = new SecureRandom();

        // 从原始密钥数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);

        // 创建一个密钥工厂，然后用它把DESKeySpec转换成SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);

        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(DES);

        // 用密钥初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);

        return cipher.doFinal(data);
    }
}