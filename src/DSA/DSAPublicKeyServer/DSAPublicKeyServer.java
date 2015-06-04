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
    private static final String keyDBFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/DSAPublicKeyServer/publicKey.db";

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
            System.out.println("DSAPublicKeyServer: started");
            initPublicKeyDB();
            System.out.println("DSAPublicKeyServer: load public KeyDB");
            s_Socket = new ServerSocket(PORT);
            System.out.println("DSAPublicKeyServer: wait of connections on Port: " + PORT);
            while (true) {
                Socket s_incoming = s_Socket.accept();
                System.out.println("DSAPublicKeyServer: accept connection on Port: " + PORT);
                Runnable r = new DSAPublicKeyServerThread(s_incoming, publicKeyDB);
                Thread t = new Thread(r);
                t.setName("DSAPublicKeyServerThread");
                System.out.println("DSAPublicKeyServer: start Thread");
                t.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println("DSAPublicKeyServer: socket closed");
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

            if (publicKeyDB.containsKey(sha.hex2String(sha.calculateHash(msg)))) {
                System.out.println(this.getClass().getName() + " Found " + msg + " in publicKeyDB");
                oos.writeObject(publicKeyDB.get(sha.hex2String(sha.calculateHash(msg))));
            } else {
                System.out.println(this.getClass().getName() + " not found " + msg + " in publicKeyDB");
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
