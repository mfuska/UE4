package DSA.Client;

import DSA.SHA256;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */
public class ClientInitPublicDSAKeyThread extends Thread {

    private String name;
    private ResultPublicKeySetter setter;

    private Socket c_socket;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;

    private int port;
    private HashMap<String, BigInteger[]> publicKeyDB;

    public ClientInitPublicDSAKeyThread(String name, int port, HashMap<String, BigInteger[]> publicKeyDB) {
        this.name = name;
        this.port = port;
        this.publicKeyDB = publicKeyDB;
    }
    public void setResultSetter(ResultPublicKeySetter setter) {
        this.setter = setter;
    }
    public void run() {
        try {
            System.out.println(this.getName() + " Open Socket.....");
           c_socket = new Socket("localhost", this.port);

           oos = new ObjectOutputStream(c_socket.getOutputStream());
           ois = new ObjectInputStream(c_socket.getInputStream());
           BigInteger[] dsaPublicKey = null;
           if (! publicKeyDB.containsKey(this.name)) {
               System.out.println(this.getName() + " Write to socket ......");
               oos.writeObject(this.name);
               System.out.println(this.getName() + " Read answer from socket ......");
               dsaPublicKey = (BigInteger[]) ois.readObject();
               publicKeyDB.put(this.name, dsaPublicKey);
            }
            this.setter.setResultSetter(publicKeyDB);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}

