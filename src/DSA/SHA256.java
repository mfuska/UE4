package DSA;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by mike on 25.05.15.
 */

public class SHA256 {
    private Boolean debug = false;
    private String SHA = "SHA-512";

    public SHA256() {
    }
    public byte[] calculateHash(String str) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest dig = null;
        dig = MessageDigest.getInstance(this.SHA);
        dig.reset();
        dig.update(str.getBytes("UTF-8"));
        return dig.digest();
    }
    public String hex2String(byte[] hashValue) {
        StringBuffer hexString = new StringBuffer();

        if (debug) System.out.println("hashlength:" + hashValue.length );
        for (int i = 0; i < hashValue.length; i++) {
            if (debug) System.out.println("hash["+ i +"]:" + hashValue[i]);
            String hex = Integer.toHexString(0xff & hashValue[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
