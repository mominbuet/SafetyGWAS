/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DataOwners;

import DB.DBQuery;
import DB.GwasEncrypted;
import DB.GwasPlaintext;
import Utilities.ChatClientEndpoint;
import Utilities.Utils;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import javax.json.Json;
import javax.json.JsonObject;

/**
 *
 * @author azizmma
 */
public class GWASOwers extends Thread {

    static String serverName = "localhost";
    static int port = 8080;
    static String id = "";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, URISyntaxException, InterruptedException {
        String destUri = "ws://" + serverName + ":" + port + "/WebGWASSGX/endpoint_gwas";//endpoint_permutation_insert

        System.out.println("Endpoint " + destUri);
        final ChatClientEndpoint clientEndPoint = new ChatClientEndpoint(new URI(destUri));
        clientEndPoint.sendMessage(Utils.getMessage("init", "DO"));
        clientEndPoint.addMessageHandler(new ChatClientEndpoint.MessageHandler() {
            @Override
            public void handleMessage(String message) {
//                Map<String,String> test = new HashMap<>();
                System.out.println("Message from server " + message);
                JsonObject jsonObject = Json.createReader(new StringReader(message)).readObject();
                String type = jsonObject.getString("type");
                if (type.equals("query")) {
                    try {
                        clientEndPoint.sendMessage(processQuery(jsonObject));
                    } catch (Exception ex) {
                        System.out.println("Exception in sending back\n" + ex.getMessage());
                    }
                } else if (type.equals("init")) {
                    id = jsonObject.getString("msg");
                }
            }

        });
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        clientEndPoint.sendMessage(Utils.getMessage("ping", ""));
                        Thread.sleep(4000);
                    } catch (Exception ex) {
                        System.out.println("ex " + ex.getMessage());
                    }
                }
            }
        });
        t.start();
        while (true) {
//            System.out.println("iteration "+iterations);
            Thread.sleep(500);
        }
        //Date d22 = new Date();

    }

    private static String processQuery(JsonObject jsonObject) {
        DBQuery dBQuery = new DBQuery();
        if (jsonObject.getInt("query") == 0) {//LD
            if (jsonObject.getInt("security") == 0) {
                GwasPlaintext snp1 = dBQuery.getFromSnip(jsonObject.getString("SNP1"));
                GwasPlaintext snp2 = dBQuery.getFromSnip(jsonObject.getString("SNP2"));
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajor1", snp1.getMajormajor())
                        .add("majormajor2", snp2.getMajormajor())
                        .add("majorminor1", snp1.getMajorminor())
                        .add("majorminor2", snp2.getMajorminor())
                        .add("minormajor1", snp1.getMinormajor())
                        .add("minormajor2", snp2.getMinormajor())
                        .add("minorminor1", snp1.getMinorminor())
                        .add("minorminor2", snp2.getMinorminor())
                        .build()
                        .toString();
            } else {
                GwasEncrypted snp1 = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"));
                GwasEncrypted snp2 = dBQuery.getFromSnipEnc(jsonObject.getString("SNP2"));
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajor1", snp1.getMajormajor())
                        .add("majormajor2", snp2.getMajormajor())
                        .add("majorminor1", snp1.getMajorminor())
                        .add("majorminor2", snp2.getMajorminor())
                        .add("minormajor1", snp1.getMinormajor())
                        .add("minormajor2", snp2.getMinormajor())
                        .add("minorminor1", snp1.getMinorminor())
                        .add("minorminor2", snp2.getMinorminor())
                        .build()
                        .toString();
            }
        } else if (jsonObject.getInt("query") == 1) {//HWE
            if (jsonObject.getInt("security") == 0) {
                GwasPlaintext snp1 = dBQuery.getFromSnip(jsonObject.getString("SNP1"));
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajor1", snp1.getMajormajor())
                        .add("majorminor1", snp1.getMajorminor())
                        .add("minormajor1", snp1.getMinormajor())
                        .add("minorminor1", snp1.getMinorminor())
                        .build()
                        .toString();
            } else {//HWE
                GwasEncrypted snp1 = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"));
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajor1", snp1.getMajormajor())
                        .add("majorminor1", snp1.getMajorminor())
                        .add("minormajor1", snp1.getMinormajor())
                        .add("minorminor1", snp1.getMinorminor())
                        .build()
                        .toString();
            }
        } else if (jsonObject.getInt("query") == 2) {//CATT
            if (jsonObject.getInt("security") == 0) {
                GwasPlaintext snp1Case = dBQuery.getFromSnip(jsonObject.getString("SNP1"), 0);
                GwasPlaintext snp1Control = dBQuery.getFromSnip(jsonObject.getString("SNP1"), 1);
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajorCase", snp1Case.getMajormajor())
                        .add("majorminorCase", snp1Case.getMajorminor())
                        .add("minormajorCase", snp1Case.getMinormajor())
                        .add("minorminorCase", snp1Case.getMinorminor())
                        .add("majormajorControl", snp1Control.getMajormajor())
                        .add("majorminorControl", snp1Control.getMajorminor())
                        .add("minormajorControl", snp1Control.getMinormajor())
                        .add("minorminorControl", snp1Control.getMinorminor())
                        .build()
                        .toString();
            } else {
                GwasEncrypted snp1Case = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"), 0);
                GwasEncrypted snp1Control = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"), 1);
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajorCase", snp1Case.getMajormajor())
                        .add("majorminorCase", snp1Case.getMajorminor())
                        .add("minormajorCase", snp1Case.getMinormajor())
                        .add("minorminorCase", snp1Case.getMinorminor())
                        .add("majormajorControl", snp1Control.getMajormajor())
                        .add("majorminorControl", snp1Control.getMajorminor())
                        .add("minormajorControl", snp1Control.getMinormajor())
                        .add("minorminorControl", snp1Control.getMinorminor())
                        .build()
                        .toString();
            }
        } else if (jsonObject.getInt("query") == 3) {//CATT
            if (jsonObject.getInt("security") == 0) {
                GwasPlaintext snp1Case = dBQuery.getFromSnip(jsonObject.getString("SNP1"), 0);
                GwasPlaintext snp1Control = dBQuery.getFromSnip(jsonObject.getString("SNP1"), 1);
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajorCase", snp1Case.getMajormajor())
                        .add("majorminorCase", snp1Case.getMajorminor())
                        .add("minormajorCase", snp1Case.getMinormajor())
                        .add("minorminorCase", snp1Case.getMinorminor())
                        .add("majormajorControl", snp1Control.getMajormajor())
                        .add("majorminorControl", snp1Control.getMajorminor())
                        .add("minormajorControl", snp1Control.getMinormajor())
                        .add("minorminorControl", snp1Control.getMinorminor())
                        .build()
                        .toString();
            } else {
                GwasEncrypted snp1Case = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"), 0);
                GwasEncrypted snp1Control = dBQuery.getFromSnipEnc(jsonObject.getString("SNP1"), 1);
                return Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query_type", jsonObject.getInt("query"))
                        .add("security", jsonObject.getInt("security"))
                        .add("from", id)
                        .add("majormajorCase", snp1Case.getMajormajor())
                        .add("majorminorCase", snp1Case.getMajorminor())
                        .add("minormajorCase", snp1Case.getMinormajor())
                        .add("minorminorCase", snp1Case.getMinorminor())
                        .add("majormajorControl", snp1Control.getMajormajor())
                        .add("majorminorControl", snp1Control.getMajorminor())
                        .add("minormajorControl", snp1Control.getMinormajor())
                        .add("minorminorControl", snp1Control.getMinorminor())
                        .build()
                        .toString();
            }
        }
        return "";
    }
}
