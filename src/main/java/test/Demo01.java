/*
package test;

import sun.security.pkcs.ContentInfo;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;

*/
/**
 * @author yangzx
 *//*

public class Demo01 {
    public static void main(String[] args) throws Exception{
        String pfx="d:/测试招标单位1-签名证书.pfx";
        X509Certificate x509=(X509Certificate)CAUtil.getCfeformPfx(pfx, "1234");

        X509Certificate[] certificates=new X509Certificate[1];
        certificates[0]=x509;
        PrivateKey privateKey=CAUtil.GetPvkformPfx(pfx, "1234");
        byte[] data="111".getBytes();
        Signature signer = Signature.getInstance(x509.getSigAlgName());
        signer.initSign(privateKey);
        signer.update(data, 0, data.length);
        byte[] signedAttributes = signer.sign();
        ContentInfo contentInfo = new ContentInfo(ContentInfo.DATA_OID, null);
        java.math.BigInteger serial = x509.getSerialNumber();

        SignerInfo si = new SignerInfo(new X500Name(x509.getIssuerDN()
                .getName()), // X500Name, issuerName,
                serial, // x509.getSerialNumber(), BigInteger serial,
                AlgorithmId.get("SHA1"), // AlgorithmId,
                // digestAlgorithmId,
                null, // PKCS9Attributes, authenticatedAttributes,
                new AlgorithmId(AlgorithmId.RSAEncryption_oid), // AlgorithmId,
                // digestEncryptionAlgorithmId,
                signedAttributes, // byte[] encryptedDigest,
                null); // PKCS9Attributes unauthenticatedAttributes) {

        SignerInfo[] signerInfos = { si };

        // 构造PKCS7数据
        AlgorithmId[] digestAlgorithmIds = { AlgorithmId.get("SHA1") };
        PKCS7 p7 = new PKCS7(digestAlgorithmIds, contentInfo, certificates,
                signerInfos);
        ByteArrayOutputStream baout = new ByteArrayOutputStream();
        p7.encodeSignedData(baout);
        // Base64编码
        String base64Result=new String(Base64.encode(baout.toByteArray()));
        System.out.println(base64Result);
    }
}
*/
