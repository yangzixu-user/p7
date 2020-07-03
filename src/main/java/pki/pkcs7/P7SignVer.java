package pki.pkcs7;

import com.koal.security.asn1.AsnObject;
import com.koal.security.asn1.DecodeException;
import com.koal.security.asn1.OctetString;
import com.koal.security.pki.pkcs12.*;
import com.koal.security.pki.pkcs12.Identifiers;
import com.koal.security.pki.pkcs7.*;
import com.koal.security.pki.pkcs8.EncryptedPrivateKeyInfo;
import com.koal.security.pki.pkcs8.PrivateKeyInfo;
import com.koal.security.pki.x509.Certificate;
import com.koal.security.util.EasyBytes;
import com.sansec.crypto.engines.RSAEngine;
import com.sansec.jce.provider.JDKAlgorithmParameters;
import koal.common.emengine.rsa.RSA;
import koal.common.emengine.util.Base64;
import koal.security.ec.util.ECKeyCreator;
import koal.security.gb.SM2Engine;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author yangzx
 */
public class P7SignVer {


    public static void main(String[] args) throws Exception {

        //读取证书
        byte[] pfxBytes = FileUtils.readFileToByteArray(new File(""));

        //解析Base64位的证书
        PFX pfx = new PFX();
        pfx.decode(Base64.decode(pfxBytes));

        //pfx证书PIN码
        char[] password = "123456".toCharArray();

        //获取私钥
        PrivateKey privateKey = getPrivateKey(pfx, password);

        //获取证书
        Certificate cert = getCertificate(pfx, password);

        //原数据
        byte[] srcData = "e077010000000997".getBytes();

        try {
            SM2Engine sm2Engine = new SM2Engine();
            byte[] signBytes = sm2Engine.sign(privateKey, srcData);
            EasyBytes.hexDump("signBytes",signBytes);
            System.out.println("=========签名结果========="+new String(Base64.encode(signBytes)));
            boolean verify = sm2Engine.verify(cert.getPublicKey(), srcData, signBytes);
            System.out.println("=========验签结果========="+verify);
        }catch (Exception e){
            RSAEngine rsaEngine = new RSAEngine();

        }



    }


    /**
     * 获取证书
     * @param pfx pfx文件
     * @param password PIN 码
     * @return
     * @throws Exception
     */
    public static Certificate getCertificate(PFX pfx,char[] password) throws Exception{
        //获取认证安全
        AuthenticatedSafe safe = pfx.getAuthenticatedSafe();
        //获取证书内容对象
        ContentInfo contentInfo = (ContentInfo) safe.getComponent(1);
        //从证书内内容对象中获取加密数据
        EncryptedData mEncryptedData =(EncryptedData) contentInfo.getContent().getActual();
        //获取加密数据
        byte[] safeContentsBytes = getData(mEncryptedData, password);
        //内容安全对象
        SafeContents safeContents = new SafeContents();
        //解码
        safeContents.decode(safeContentsBytes);
        //获取安全环境
        SafeBag safeBag = safeContents.getSafeBag(Identifiers.certBag);
        //获取证书包装
        CertBag certBag = (CertBag)safeBag.getBagValue().getActual();
        //获取八位位流
        OctetString certOctetString = (OctetString)certBag.getCertValue().getActual();
        Certificate cert = new Certificate();
        cert.decode((byte[]) certOctetString.getValue());
        return cert;
    }

    /**
     * 获取加密数据 data（info）
     * @param mEncryptedData 加密数据
     * @param password PIN码
     * @return
     */
    public static byte[] getData(EncryptedData mEncryptedData,char[] password) throws Exception {
        //获取加密内容信息
        EncryptedContentInfo encryptedContentInfo = mEncryptedData.getEncryptedContentInfo();
        //从加密内容信息中获取内容的加密算法标识符
        ContentEncryptionAlgorithmIdentifier algId = encryptedContentInfo.getContentEncryptionAlgorithm();
        //获取构造PKCS12证书参数
        PKCS12PBEParams parameters =(PKCS12PBEParams) algId.getParameters().getActual();
        //规则
        PBEParameterSpec paramSpec = new PBEParameterSpec((byte[]) parameters.getSalt().getValue(),
                parameters.getIterations().getIntValue());
        //获取加密内容信息的值
        byte[] cipherText = (byte[]) encryptedContentInfo.getEncryptedContent().getValue();
        //从证书证获取算法名称
        String algorithmName  = algId.getAlgorithm().toString();
        //使用私药证书创建秘密密钥工厂
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithmName);
        //得到密钥
        SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(password));
        //获取密码
        Cipher cipher = Cipher.getInstance(algorithmName);
        //初始化
        cipher.init(Cipher.DECRYPT_MODE,secretKey,paramSpec);
        return cipher.doFinal(cipherText);

    }



    public static PrivateKey getPrivateKey(PFX pfx,char[] password) throws Exception {
        AuthenticatedSafe safe = pfx.getAuthenticatedSafe();
        ContentInfo info = (ContentInfo)safe.getComponent(0);
        Data content = (Data) info.getContent().getActual();
        byte[] value = (byte[]) content.getValue();
        SafeContents safeContents = new SafeContents();
        safeContents.decode(value);
        SafeBag safeBag = safeContents.getSafeBag(Identifiers.pkcs8ShroudedKeyBag);
        //获取私钥信息
        EncryptedPrivateKeyInfo epki = (EncryptedPrivateKeyInfo) safeBag.getBagValue().getActual();
        //获取私钥
        return getPrivateKey(epki,password);
    }

    public static PrivateKey getPrivateKey(EncryptedPrivateKeyInfo epki ,char[] password) throws Exception {
        //获取加密算法
        String algorithm = epki.getEncryptionAlgorithm().getAlgorithm().toString();
        SecretKeyFactory secretKeyFactory =  SecretKeyFactory.getInstance(algorithm);
        SecretKey secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(password));
        PKCS12PBEParams params = (PKCS12PBEParams) epki.getEncryptionAlgorithm().getParameters().getActual();

        PBEParameterSpec paramsSpec = new PBEParameterSpec((byte[]) params.getSalt().getValue(), params.getIterations().getIntValue());

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE,secretKey,paramsSpec);
        byte[] plaintext = cipher.doFinal((byte[]) epki.getEncryptedData().getValue());
        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo();
        privateKeyInfo.decode(plaintext);
        if (com.koal.security.pki.pkcs1.Identifiers.rsaEncryption.equals(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm())){
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(plaintext));
        }else {
            return ECKeyCreator.createECPrivateKey(plaintext);
        }
    }


}
