package pki.pkcs7;


/**
 * @author yangzx
 */
public class Test {

    public static void main(String[] args) throws Exception {
    /*    String pfxpath = "d:/work/cert/������4.pfx";
        String s = "d:/work/cert/koal1231.pfx";
        //��ȡ֤��
        PFX pfx = PKCS7Utils.getPFX(pfxpath);
        System.out.println("PFX     "+pfx);
        String password = "123456";
        char[] pass = "123456".toCharArray();
        //��ȡ˽Կ
        PrivateKey privateKey = PKCS7Utils.getPrivateKey(pfx, pass);
        System.out.println("privateKey     "+privateKey);
        //ǩ�����ݣ�
        String data = "e077010000000997";
        byte[] oridata = data.getBytes();
        byte[] bytes = Pkcs7Utils.p7Sign(oridata, pfxpath, "123456");
        System.out.println(Base64.encodeBase64String(bytes));
*/


        char[] chars = "asdfsad".toCharArray();
        System.out.println(chars[-126]);

    }





}
