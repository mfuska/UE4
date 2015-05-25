package DSA.DSAPublicKeyServer;

import DSA.SHA256;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */


public class DSAPublicKeyServer {
    private static final int PORT = 50001;
    private static ServerSocket s_Socket;
    private static HashMap<String, BigInteger[]> publicKeyDB;
    private static final String keyDBFile = "/Users/mike/2sem/Kryptographische Protokolle/UE4/src/DSA/DSAPublicKeyServer/publicKey.db";

    private static void initPublicKeyDB() throws IOException {
        publicKeyDB = new HashMap<String, BigInteger[]>();
        File file = new File(keyDBFile);
        BufferedReader in = new BufferedReader(new FileReader(file));
        String line = null;
        while ((line = in.readLine()) != null) {
            String[] strArray = line.split(" ");
            BigInteger[] bigArray = {
                new BigInteger(strArray[1]),
                new BigInteger(strArray[2]),
                new BigInteger(strArray[3]),
                new BigInteger(strArray[4])
            };
            publicKeyDB.put(strArray[0], bigArray);
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("DSAPublicKeyServerThread: up and running");
            initPublicKeyDB();
            s_Socket = new ServerSocket(PORT);

            while (true) {
                Socket s_incoming = s_Socket.accept();

                Runnable r = new DSAPublicKeyServerThread(s_incoming, publicKeyDB);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println("DSAPublicKeyServer: closed");
                s_Socket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }
}

class DSAPublicKeyServerThread implements Runnable {
    private Socket socket;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;
    private HashMap<String, BigInteger[]> publicKeyDB;

    private SHA256 sha;
    public DSAPublicKeyServerThread(Socket s, HashMap<String, BigInteger[]> publicKeyDB) {
        this.socket = s;
        this.publicKeyDB = publicKeyDB;
        sha = new SHA256();
    }

    public void run() {
        try {
            System.out.println(this.getClass().getName() + ": getMMessage");
            this.ois = new ObjectInputStream(socket.getInputStream());
            this.oos = new ObjectOutputStream(socket.getOutputStream());
            String msg = (String)ois.readObject();
            System.out.println(this.getClass().getName() + " Search for " + msg + " in publicKeyDB");

            if (publicKeyDB.containsKey(sha.calculateHash(msg))) {
                System.out.println(this.getClass().getName() + "Found " + msg + " in publicKeyDB");
                oos.writeObject(publicKeyDB.get(sha.calculateHash(msg)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println(this.getClass().getName() + ": close()");
                this.ois.close();
                this.oos.flush();
                this.oos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
