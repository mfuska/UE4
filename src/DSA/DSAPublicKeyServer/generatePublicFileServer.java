package DSA.DSAPublicKeyServer;

import DSA.RSA;
import DSA.SHA256;
import DSA.DSA;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by mike on 25.05.15.
 */
public class generatePublicFileServer {
    private static SHA256 sha;
    private static RSA rsa;
    private static DSA dsa_c;
    private static DSA dsa_d;
    private static DSA dsa_m;
    private static SecureRandom random = new SecureRandom();
    private static int BITLENGTH = 2048;


    public static void main(String[] args) {
        FileWriter os_publicKey = null;
        FileWriter os_privateKey = null;
        FileWriter os_privateKeyRSA = null;
        try {

            sha = new SHA256();
            rsa = new RSA();
            System.out.println("1");
            dsa_c = new DSA();
            System.out.println("2");
            dsa_d = new DSA();
            System.out.println("3");
            dsa_m = new DSA();

            System.out.println("4");
            os_publicKey = new FileWriter("publicKey.db");
            os_privateKey = new FileWriter("privateKey.db");
            os_privateKeyRSA = new FileWriter("privateKeyRSA.db");
            System.out.println("5");

            os_privateKeyRSA.write(rsa.getRSAParameter());
            System.out.println("6");

            os_publicKey.write(sha.hex2String(sha.calculateHash("carina")) + " " + dsa_c.getPublicKeyString());
            os_privateKey.write(sha.hex2String(sha.calculateHash("carina")) + " " + rsa.encrypt(new BigInteger(dsa_c.getPrivateKeyString())).toString());

            System.out.println("7");
            os_publicKey.write(sha.hex2String(sha.calculateHash("daniel")) + " " + dsa_d.getPublicKeyString());
            os_privateKey.write(sha.hex2String(sha.calculateHash("daniel")) + " " + rsa.encrypt(new BigInteger(dsa_d.getPrivateKeyString())).toString());

            System.out.println("1");
            os_publicKey.write(sha.hex2String(sha.calculateHash("michi")) + " " + dsa_m.getPublicKeyString());
            os_privateKey.write(sha.hex2String(sha.calculateHash("michi")) + " " + rsa.encrypt(new BigInteger(dsa_m.getPrivateKeyString())).toString());
            System.out.println("9");
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
                os_privateKeyRSA.flush();
                os_privateKeyRSA.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}

