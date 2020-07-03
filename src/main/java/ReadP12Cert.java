import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

public class ReadP12Cert {
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
            //String priStr = Base64.getEncoder().encodeToString(prikey.getEncoded());
            System.out.println("@@@@@@@@@@@@@@@=========" + priStr);
            Certificate cert = keyStore.getCertificate(keyAlias);
            PublicKey pubkey = cert.getPublicKey();

            //获取公钥字符串
            String pubStr = Base64.encode(pubkey.getEncoded());
            System.out.println("编码：：：：：：：" + pubStr);
            System.out.println("解码：：：：：：：" + Base64.decode(pubStr));
            //System.out.println(enumeration.hasMoreElements());
            //System.out.println("cert class =" + cert.getClass().getName());
            System.out.println("cert =" + cert);

            System.out.println("public keyStr = " + pubStr);
            System.out.println("private keyStr = " + priStr);
            System.out.println("======================开始签名=========================");
            //使用自己的私钥进行签名
            String signed = mySign(data, priStr, SIGN_ALGORITHMS);
            System.out.println("原数据====" + data);
            System.out.println("签名数据===" + signed);
            //使用自己的公钥进行验签
            boolean b = myDoCheck(data, signed, pubStr, SIGN_ALGORITHMS);
            System.out.println("验签====" + b);
        } catch (KeyStoreException e) {
            throw new Exception("该证书模板不存在");
        } catch (FileNotFoundException e) {
            throw new Exception("加载文件异常");
        }


    }

    //私钥签名
    public static String mySign(String data, String priKeyStr, String singAlgorithms) {
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

    //公钥验签
    public static boolean myDoCheck(String data, String sign, String pubKey, String signAlgorithms) {
        try {
            //创建密钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //生成公钥对象
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decode(pubKey)));
            //signature签名验签的对象
            Signature signature = Signature.getInstance(signAlgorithms);
            signature.initVerify(publicKey);
            signature.update(data.getBytes());
            //验签
            return signature.verify(Base64.decode(sign));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }
}