/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Researcher;

import Utilities.ChatClientEndpoint;
import Utilities.Utils;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import javax.json.Json;
import javax.json.JsonObject;

/**
 *
 * @author azizmma
 */
public class Queries {

    static String serverName = "localhost";
    static int port = 8080;
    static int timeout = 5 * 1000;
    static int queryCount = 0;
    static int highest = 10;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, URISyntaxException, InterruptedException {
        String destUri = "ws://" + serverName + ":" + port + "/WebGWASSGX/endpoint_gwas";//endpoint_permutation_insert
        System.out.println("Endpoint " + destUri);
        Date d11 = new Date();

        final ChatClientEndpoint clientEndPoint = new ChatClientEndpoint(new URI(destUri));
        clientEndPoint.addMessageHandler(new ChatClientEndpoint.MessageHandler() {
            @Override
            public void handleMessage(String message) {
                JsonObject jsonObject = Json.createReader(new StringReader(message)).readObject();
                String type = jsonObject.getString("type");
                if (type.equals("query_results")) {
                    System.out.println("received " + message);
                    if (queryCount < highest) {
                        try {
                            String sending2 = getQuery();
                            clientEndPoint.sendMessage(sending2);
                            System.out.println("sent query " + queryCount + " " + sending2);
                            queryCount++;
                        } catch (IOException ex) {
                            System.out.println(ex.getMessage());
                        }
                    }

                }
            }
        });

//        JsonObjectBuilder jsonObjectBuilder = Json.createObjectBuilder();
//        JsonObjectBuilder snps = Json.createObjectBuilder();
        String sending = getQuery();

        clientEndPoint.sendMessage(sending);
        System.out.println("sent query " + queryCount + " " + sending);
        queryCount++;
        //ping commands to stay alive
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        clientEndPoint.sendMessage(Utils.getMessage("ping", ""));
                        Thread.sleep(timeout);//5sec delay pings
                    } catch (Exception ex) {
                        System.out.println("exception " + ex.getMessage());
                    }
                }
            }
        });
        t.start();
        while (queryCount < highest) {
//            System.out.println("iteration "+iterations);
            Thread.sleep(500);
        }

        Date d22 = new Date();
        System.out.println("Total Running time " + (double) (d22.getTime() - d11.getTime()));
//        t.join();
        System.exit(1); 
    }

    private static String getQuery() {
        return Json.createObjectBuilder()
                .add("type", "query")
                .add("query", 0)//LD=0,HWE=1,CATT=2,FET=2
                .add("security", 0)//0 for plaintext
                .add("SNP1", "rs100010" )
                .add("SNP2", "rs100033")
                .add("case", "0")
                .build()
                .toString();
    } 
}
