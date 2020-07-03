import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;

/**
 * @author yangzx
 */
public class Test {

    static String data = "e077010000000997";
    public static final String SIGN_ALGORITHMS = "SHA256withRSA";

    public static void main(String[] args) throws Exception {
        //密钥证书文件地址
        final String keyStoreFile = "D:/work/cert/koal1231.pfx/";
        //密钥文件打开密码
        final String keyPassword = "123456";
        //密钥别名
        String keyAlias = "alias";

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(keyStoreFile);
            char[] nPassword = null;
            if (keyPassword == null) {
                nPassword = null;
            } else {
                nPassword = keyPassword.toCharArray();
            }
            keyStore.load(fis, nPassword);
            fis.close();
            System.out.println("keyStore Type :" + keyStore.getType());
            //使用
            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                //这里面只有一个证书提供者，没有必要使用while循环,只是知道有这个东西存在
                System.out.println("-------------->nothing<-------------------");
                keyAlias = (String) enumeration.nextElement();
            }
            //判断entry是否存在 返回true存在
            System.out.println("is key entry=" + keyStore.isKeyEntry(keyAlias));
            //自己的获取私钥
            PrivateKey prikey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
            //获取私钥字符串
            String priStr = Base64.encode(prikey.getEncoded());
            System.out.println(priStr);
            Certificate cert = keyStore.getCertificate(keyAlias);
            //使用自己的私钥进行签名
            String signed = mySign(data, priStr, SIGN_ALGORITHMS);
            System.out.println("原数据====" + data);
            System.out.println("签名数据===" + signed);
        } catch (KeyStoreException e) {
            throw new Exception("该证书模板不存在");
        } catch (FileNotFoundException e) {
            throw new Exception("加载文件异常");
        }


    }

    public static String getPrivateKeyStr(String PFXPath,String password ) throws Exception{
        //密钥证书文件地址
        final String keyStoreFile = "D:/work/cert/koal1231.pfx/";
        //密钥文件打开密码
        final String keyPassword = "123456";
        //密钥别名
        String keyAlias = "alias";

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(keyStoreFile);
            char[] nPassword = null;
            if (keyPassword == null) {
                nPassword = null;
            } else {
                nPassword = keyPassword.toCharArray();
            }
            keyStore.load(fis, nPassword);
            fis.close();
            System.out.println("keyStore Type :" + keyStore.getType());
            //使用
            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                //这里面只有一个证书提供者，没有必要使用while循环,只是知道有这个东西存在
                System.out.println("-------------->nothing<-------------------");
                keyAlias = (String) enumeration.nextElement();
            }
            //判断entry是否存在 返回true存在
            System.out.println("is key entry=" + keyStore.isKeyEntry(keyAlias));
            //自己的获取私钥
            PrivateKey prikey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
            //获取私钥字符串
            String priStr = Base64.encode(prikey.getEncoded());
            System.out.println(priStr);
            Certificate cert = keyStore.getCertificate(keyAlias);
            //使用自己的私钥进行签名
            String signed = mySign(data, priStr, SIGN_ALGORITHMS);
            System.out.println("原数据====" + data);
            System.out.println("签名数据===" + signed);
        } catch (KeyStoreException e) {
            throw new Exception("该证书模板不存在");
        } catch (FileNotFoundException e) {
            throw new Exception("加载文件异常");
        }
        return null;
    }

    //私钥签名
    public static String mySign(String data, String priKeyStr, String singAlgorithms) throws Exception{
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(priKeyStr));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //generatePrivate(keySpec)根据私钥PKCS8模板规范创建私钥对象
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            Signature signature = Signature.getInstance(singAlgorithms);
            signature.initSign(privateKey);
            signature.update(data.getBytes());
            //签名
            byte[] signed = signature.sign();
            return Base64.encode(signed);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return null;
    }







}
