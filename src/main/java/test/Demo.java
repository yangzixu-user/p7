package test;

import com.koal.security.util.PKCS7Utils;
import org.apache.commons.net.util.Base64;


/**
 * @author yangzx
 */
public class Demo {
    public static void main(String[] args) throws Exception {
        byte[] bytes = PKCS7Utils.signP7Detach("123456".getBytes(), "d:/work/cert/杨子旭4.pfx", "123456");
        System.out.println(Base64.encodeBase64String(bytes));
    }
}
