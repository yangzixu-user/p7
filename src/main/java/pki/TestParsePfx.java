package pki;


import com.koal.security.asn1.OctetString;
import com.koal.security.pki.pkcs1.Identifiers;
import com.koal.security.pki.pkcs12.*;
import com.koal.security.pki.pkcs7.*;
import com.koal.security.pki.pkcs8.EncryptedPrivateKeyInfo;
import com.koal.security.pki.pkcs8.PrivateKeyInfo;
import com.koal.security.pki.x509.Certificate;
import com.koal.security.util.EasyBytes;
import koal.common.emengine.util.Base64;
import koal.security.ec.util.ECKeyCreator;
import koal.security.gb.SM2Engine;
import org.apache.commons.io.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author: huangff
 * @date: 2020/7/2
 * @description: 解析PFX证书
 */
public class TestParsePfx {

    public static void main(String[] args) throws Exception {
        // 读取PFX证书
        byte[] pfxBytes = FileUtils.readFileToByteArray(new java.io.File("d:/work/cert/test.pfx"));
        PFX pfx = new PFX();
        // 解析Base64的证书
        pfx.decode(Base64.decode(pfxBytes));

        // PFX证书PIN码
        char[] password = "123456".toCharArray();

        // 获取私钥
        PrivateKey priKey = getPrivateKey(pfx, password);
        
        // 获取证书
        Certificate cert = getCertificate(pfx, password);

        byte[] srcData = "e077010000000997".getBytes();
        SM2Engine sm2Engine = new SM2Engine();
        byte[] sigBytes = sm2Engine.sign(priKey, srcData);

        EasyBytes.hexDump("sigBytes", sigBytes);

        System.out.println("======签名结果======" + new String(Base64.encode(sigBytes)));

        boolean result = sm2Engine.verify(cert.getPublicKey(), srcData, sigBytes);
        System.out.println("==============签名验签结果==========" + result);
    }

    public static Certificate getCertificate(PFX pfx, char[] password) throws Exception {
        AuthenticatedSafe safe = pfx.getAuthenticatedSafe();
        ContentInfo contentInfo = (ContentInfo) safe.getComponent(1);
        EncryptedData mEncryptedData = (EncryptedData) contentInfo.getContent().getActual();
        byte[] safeContentsBytes = getData(mEncryptedData, password);
        SafeContents safeContents = new SafeContents();
        safeContents.decode(safeContentsBytes);
        SafeBag safeBag = safeContents.getSafeBag(com.koal.security.pki.pkcs12.Identifiers.certBag);
        CertBag certBag = (CertBag) safeBag.getBagValue().getActual();
        OctetString certOctetString = (OctetString) certBag.getCertValue().getActual();
        Certificate cert = new Certificate();
        cert.decode((byte[]) certOctetString.getValue());
        return cert;
    }

    public static byte[] getData(EncryptedData mEncryptedData, char[] password) throws Exception {
        EncryptedContentInfo encryptedContentInfo = mEncryptedData.getEncryptedContentInfo();
        ContentEncryptionAlgorithmIdentifier algId = encryptedContentInfo.getContentEncryptionAlgorithm();
        PKCS12PBEParams parameters = (PKCS12PBEParams) algId.getParameters().getActual();

        PBEParameterSpec paramSpec = new PBEParameterSpec((byte[]) parameters.getSalt().getValue(), parameters
                .getIterations().getIntValue());

        byte[] cipherText = (byte[]) encryptedContentInfo.getEncryptedContent().getValue();

        String algorithmName = algId.getAlgorithm().toString();
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithmName);
        SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(algorithmName);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);

        return cipher.doFinal(cipherText);

    }

    public static PrivateKey getPrivateKey(PFX pfx, char[] password) throws Exception {
        AuthenticatedSafe safe = pfx.getAuthenticatedSafe();
        ContentInfo info = (ContentInfo) safe.getComponent(0);
        Data content = (Data) info.getContent().getActual();
        byte[] value = (byte[]) content.getValue();
        SafeContents safeContents = new SafeContents();
        safeContents.decode(value);
        SafeBag safeBag = safeContents.getSafeBag(com.koal.security.pki.pkcs12.Identifiers.pkcs8ShroudedKeyBag);
        EncryptedPrivateKeyInfo epki = (EncryptedPrivateKeyInfo) safeBag.getBagValue().getActual();
        // 获取私钥
        return getPrivateKey(epki, password);
    }

    public static PrivateKey getPrivateKey(EncryptedPrivateKeyInfo ePri, char[] password) throws Exception {
        String algorithm = ePri.getEncryptionAlgorithm().getAlgorithm().toString();
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        SecretKey secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(password));
        PKCS12PBEParams params = (PKCS12PBEParams) ePri.getEncryptionAlgorithm().getParameters().getActual();

        PBEParameterSpec paramSpec = new PBEParameterSpec((byte[]) params.getSalt().getValue(), params.getIterations().getIntValue());

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);

        byte[] plaintext = cipher.doFinal((byte[]) ePri.getEncryptedData().getValue());

        PrivateKeyInfo privateKeyInfo = new PrivateKeyInfo("privateKeyInfo");
        privateKeyInfo.decode(plaintext);

        if (Identifiers.rsaEncryption.equals(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(plaintext));
        } else {
            return ECKeyCreator.createECPrivateKey(plaintext);
        }

    }

}
