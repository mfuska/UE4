package DSA.Client;

import DSA.SHA256;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

/**
 * Created by mike on 04.06.15.
 */
public class ClientInitPublicAuthServerKeyThread extends Thread {

    private String keyDBFile;
    private ResultPublicAuthServerSetter setter;

    private HashMap<String, BigInteger[]> publicKeyDB;
    private String name;
    public ClientInitPublicAuthServerKeyThread(HashMap<String, BigInteger[]> publicKeyDB, String keyDBFile) {
        this.publicKeyDB = publicKeyDB;
        this.keyDBFile = keyDBFile;
        this.name = new String("authServer");
    }
    public void setResultSetter(ResultPublicAuthServerSetter setter) {
        this.setter = setter;
    }
    public void run() {
        System.out.println(this.getName() + " Started....");
        File file = new File(keyDBFile);
        BufferedReader in = null;
        SHA256 sha = new SHA256();
        try {
            in = new BufferedReader(new FileReader(file));
            String line = null;
            while ((line = in.readLine()) != null) {
                String[] strArray = line.split(" ");
                if ( strArray[0].equals(sha.hex2String(sha.calculateHash(this.name)))) {
                    System.out.println(this.getName() + " Found publicKey for user: " + this.name);
                    BigInteger[] bigArray = {
                            new BigInteger(strArray[1]),
                            new BigInteger(strArray[2]),
                            new BigInteger(strArray[3]),
                            new BigInteger(strArray[4])
                    };
                    publicKeyDB.put(this.name, bigArray);
                    this.setter.setResultSetter(publicKeyDB);
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
