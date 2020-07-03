package test;

/**
 * @author yangzx
 */
//我认为你需要以下2castle罐产生PKCS7数字签名： bcprov-jdk15on-147.jar（对JDK 1.5-JDK 1.7） bcmail-jdk15on-147.jar（对JDK 1.5-JDK 1.7） 你可以从这里下载的castle罐子。 你需要设置你的密钥库与公共和私有密钥对。 你只需要私钥生成的数字签名和公钥来验证它。 这里是你如何PKCS7标志内容（异常处理不再赘述）：
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.net.util.Base64;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

public final class PKCS7Signer {
    private static final String PATH_TO_KEYSTORE = "d:/work/cert/杨子旭4.pfx";
    private static  String KEY_ALIAS_IN_KEYSTORE = "my-private-key";
    private static final String KEYSTORE_PASSWORD = "123456";
    private static final String SIGNATUREALGO = "SHA1withRSA";
    public PKCS7Signer() {
    }
    KeyStore loadKeyStore() throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream(PATH_TO_KEYSTORE);
        keystore.load(is, KEYSTORE_PASSWORD.toCharArray());
        Enumeration<String> enumeration = keystore.aliases();
        while (enumeration.hasMoreElements()) {
            //这里面只有一个证书提供者，没有必要使用while循环,只是知道有这个东西存在
            System.out.println("-------------->nothing<-------------------");
            KEY_ALIAS_IN_KEYSTORE = enumeration.nextElement();
        }
        return keystore;
    }
    CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Certificate[] certchain = (Certificate[]) keystore.getCertificateChain(KEY_ALIAS_IN_KEYSTORE);
        final List<Certificate> certlist = new ArrayList<Certificate>();
        for (int i = 0, length = certchain == null ? 0 : certchain.length; i < length; i++) {
            certlist.add(certchain[i]);
        }
        Store certstore = new JcaCertStore(certlist);
        Certificate cert = keystore.getCertificate(KEY_ALIAS_IN_KEYSTORE);
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATUREALGO).setProvider("BC").
                build((PrivateKey) (keystore.getKey(KEY_ALIAS_IN_KEYSTORE, KEYSTORE_PASSWORD.toCharArray())));
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) cert));
        generator.addCertificates(certstore);
        return generator;
    }
    byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws Exception {
        CMSTypedData cmsdata = new CMSProcessableByteArray(content);
        CMSSignedData signeddata = generator.generate(cmsdata, true);
        return signeddata.getEncoded();
    }
    public static void main(String[] args) throws Exception {
        PKCS7Signer signer = new PKCS7Signer();
        KeyStore keyStore = signer.loadKeyStore();
        CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore);
        String content = "e077010000000997";
        byte[] signedBytes = signer.signPkcs7(content.getBytes("UTF-8"), signatureGenerator);
        System.out.println("20140826fixed: Adjust SignerInfos class compatibility with WIN7.");
        System.out.println(Base64.encodeBase64String(signedBytes));



        }


}

