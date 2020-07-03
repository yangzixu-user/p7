package test;

import java.io.ByteArrayInputStream;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * @author yangzx
 */
public class Demo02 {

    public Boolean SignedData_Verify(byte[] signData,byte[] signedData,byte[] cert){
        boolean verifyRet=false;
        try {

            //创建工厂
            CertificateFactory factory = CertificateFactory.getInstance("x509");
            //创建509证书对象
            ByteArrayInputStream ois = new ByteArrayInputStream(cert);
            Certificate oCert = factory.generateCertificate(ois);
            //创建签名对象
            Signature oSign = Signature.getInstance("SHA256withRSA");
            //传入签名原文
            oSign.update(signData);
            //验证数字签名
            verifyRet = oSign.verify(signedData);

        }catch (Exception e){
           verifyRet = false;
           e.printStackTrace();
            System.out.println("验证数字签名失败");
        }
        return verifyRet;
    }


}
