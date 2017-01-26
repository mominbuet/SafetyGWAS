/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CloudSGX;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import javax.json.Json;
import javax.json.JsonObject;

/**
 *
 * @author azizmma
 */
public class Server extends Thread {

    private ServerSocket serverSocket;
    static final int timeout = 5 * 60 * 1000;//5min

    public Server(int port) throws SocketException, IOException {
        serverSocket = new ServerSocket(port);
        serverSocket.setSoTimeout(timeout);
    }

    public void run() {
        while (true) {
            try {
                System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
                Socket server = serverSocket.accept();
                System.out.println("Just connected to " + server.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(server.getInputStream());
                String input = in.readUTF();
                System.out.println(input);
                JsonObject jsonObject = Json.createReader(new StringReader(input)).readObject();

            } catch (Exception ex) {
                System.out.println("Error " + ex.getMessage());
            }
        }
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {
        Thread t = new Server(8899);
        t.start();
    }
}
