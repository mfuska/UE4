package DSA.DSAPublicKeyServer;

import DSA.SHA256;
import DSA.DSA;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by mike on 25.05.15.
 */
public class generatePublicFileServer {
    private static SHA256 sha;
    private static DSA dsa_c;
    private static DSA dsa_d;
    private static DSA dsa_m;
    private static DSA dsa_as;
    private static SecureRandom random = new SecureRandom();
    private static int BITLENGTH = 2048;


    public static void main(String[] args) {
        FileWriter os_publicKey = null;
        FileWriter os_privateKey = null;
        try {

            sha = new SHA256();
            /*
            dsa_c = new DSA();
            dsa_d = new DSA();
            dsa_m = new DSA();

            *os_publicKey = new FileWriter("publicKey.db");
            os_privateKey = new FileWriter("privateKey.db");

            os_publicKey.write(sha.hex2String(sha.calculateHash("carina")) + " " + dsa_c.getPublicKeyString() + "\n");
            os_privateKey.write(sha.hex2String(sha.calculateHash("carina")) + " " + dsa_c.getPrivateKeyString() + "\n");

            os_publicKey.write(sha.hex2String(sha.calculateHash("daniel")) + " " + dsa_d.getPublicKeyString()  + "\n");
            os_privateKey.write(sha.hex2String(sha.calculateHash("daniel")) + " " + dsa_d.getPrivateKeyString()  + "\n");

            os_publicKey.write(sha.hex2String(sha.calculateHash("michi")) + " " + dsa_m.getPublicKeyString()  + "\n");
            os_privateKey.write(sha.hex2String(sha.calculateHash("michi")) + " " + dsa_m.getPrivateKeyString()  + "\n");
            */

            dsa_as = new DSA();
            os_publicKey = new FileWriter("authServerPublicKey.db");
            os_privateKey = new FileWriter("authServerPrivateKey.db");
            os_publicKey.write(sha.hex2String(sha.calculateHash("authServer")) + " " + dsa_as.getPublicKeyString()  + "\n");
            os_privateKey.write(sha.hex2String(sha.calculateHash("authServer")) + " " + dsa_as.getPrivateKeyString()  + "\n");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                os_privateKey.flush();
                os_privateKey.close();
                os_publicKey.flush();
                os_publicKey.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

