package pki.pkcs7;


/**
 * @author yangzx
 */
public class Test {

    public static void main(String[] args) throws Exception {
    /*    String pfxpath = "d:/work/cert/杨子旭4.pfx";
        String s = "d:/work/cert/koal1231.pfx";
        //获取证书
        PFX pfx = PKCS7Utils.getPFX(pfxpath);
        System.out.println("PFX     "+pfx);
        String password = "123456";
        char[] pass = "123456".toCharArray();
        //获取私钥
        PrivateKey privateKey = PKCS7Utils.getPrivateKey(pfx, pass);
        System.out.println("privateKey     "+privateKey);
        //签名数据：
        String data = "e077010000000997";
        byte[] oridata = data.getBytes();
        byte[] bytes = Pkcs7Utils.p7Sign(oridata, pfxpath, "123456");
        System.out.println(Base64.encodeBase64String(bytes));
*/


        char[] chars = "asdfsad".toCharArray();
        System.out.println(chars[-126]);

    }





}
