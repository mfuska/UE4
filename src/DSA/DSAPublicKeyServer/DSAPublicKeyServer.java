package DSA.DSAPublicKeyServer;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Created by mike on 25.05.15.
 */


public class DSAPublicKeyServer {
    private static final int PORT = 50001;
    private static ServerSocket s_Socket;

    public static void main(String[] args) {
        try {
            System.out.println("DSAPublicKeyServerThread: up and running");
            s_Socket = new ServerSocket(PORT);

            while (true) {
                Socket s_incoming = s_Socket.accept();

                Runnable r = new DSAPublicKeyServerThread(s_incoming);
                Thread t = new Thread(r);
                t.setName("DSAPublicKeyServerThread");
                t.start();
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

    public DSAPublicKeyServerThread(Socket s) {
        this.socket = s;
    }

    public void run() {
        try {
            System.out.println(this.getClass().getName() + ": getMMessage");
            this.ois = new ObjectInputStream(socket.getInputStream());
            this.oos = new ObjectOutputStream(socket.getOutputStream());
            //Message msgObj = (Message)ois.readObject();
            //oos.writeObject(msgSend);

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
