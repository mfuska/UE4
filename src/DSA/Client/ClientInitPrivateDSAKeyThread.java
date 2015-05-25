package DSA.Client;

import DSA.SHA256;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

/**
 * Created by mike on 25.05.15.
 */
public class ClientInitPrivateDSAKeyThread extends Thread {

    private String keyDBFile;
    private String name;
    private ResultPrivateKeySetter setter;

    public ClientInitPrivateDSAKeyThread(String name, String keyDBFile) {
        this.name = name;
        this.keyDBFile = keyDBFile;
    }
    public void setResultSetter(ResultPrivateKeySetter setter) {
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
                    System.out.println(this.getName() + "Found privatKey for user: " + this.name);
                    BigInteger[] bigArray = {
                            new BigInteger(strArray[1]),
                            new BigInteger(strArray[2]),
                            new BigInteger(strArray[3]),
                            new BigInteger(strArray[4])
                    };
                    this.setter.setResultSetter(bigArray);
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
