/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cs.umanitoba.ca.webgwassgx;

import Utilities.FisherTest;
import Utilities.Paillier;
import Utilities.Utils;
import static Utilities.Utils.executeConsoleCommand;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import javax.json.Json;
import javax.json.JsonObject;
import javax.websocket.OnClose;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

/**
 *
 * @author azizmma
 */
@ServerEndpoint("/endpoint_gwas")
public class ServerGWAS {

    static List<DataOwner> dataOwnerSessions = new ArrayList<>();
    static Map<String, String> sentQueries = new HashMap<>();
    static int querySent = 0;
    static Session researcher; 

    @OnMessage 
    public void onMessage(String message, Session session) throws IOException {
        JsonObject jsonObject = Json.createReader(new StringReader(message)).readObject();

        String type = jsonObject.getString("type");
        if (!type.equals("ping")) {  
            System.out.println("message " + message);
            if (type.equals("init") && jsonObject.getString("msg").equals("DO")) {
                DataOwner dataOwner = new DataOwner(session);
                session.getBasicRemote().sendText(Utils.getMessage("init", "owner" + dataOwner.id));
                dataOwnerSessions.add(dataOwner);

            } else if (type.equals("query")) {
                for (DataOwner dataOwnerSession : dataOwnerSessions) {
                    if (dataOwnerSession.active) {
                        if (dataOwnerSession.session.isOpen()) {
                            sentQueries.put("owner" + dataOwnerSession.id, "");
                            dataOwnerSession.session.getBasicRemote().sendText(message);
                            querySent++;
                        } else {
                            dataOwnerSession.active = false;
                        }
                    }

                }
                System.out.println("query sent " + querySent);
                researcher = session;
            } else if (type.equals("query_results")) {
                sentQueries.put(jsonObject.getString("from"), message);
                querySent--;
                if (querySent == 0) {//all done

                    switch (jsonObject.getInt("query_type")) {
                        case 0:
                            processLD(jsonObject.getInt("security"));
                            break;
                        case 1:
                            processHWE(jsonObject.getInt("security"));
                            break;
                        case 2:
                            processCATT(jsonObject.getInt("security"));
                            break;
                        case 3:
                            processFET(jsonObject.getInt("security"));
                            break;
                    }

                }
            }
        }
    }

    @OnOpen
    public void onOpen(Session peer) {
//        peers.add(peer);

    }

    @OnClose
    public void onClose(Session peer) {
        for (DataOwner dataOwnerSession : dataOwnerSessions) {
            if (peer.getId().equals(dataOwnerSession.session.getId())) {
                dataOwnerSession.active = false;
            }
        }
    }

    private void processLD(int secure) throws IOException {

        if (secure == 0) {
            int N1_AA = 0, N1_Aa = 0, N1_aA = 0, N1_aa = 0, N2_AA = 0, N2_Aa = 0, N2_aA = 0, N2_aa = 0;
            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N1_AA += res.getInt("majormajor1");
                N2_AA += res.getInt("majormajor2");
                N1_aA += res.getInt("minormajor1");
                N2_aA += res.getInt("minormajor2");
                N1_aa += res.getInt("minorminor1");
                N2_aa += res.getInt("minorminor2");
                N1_Aa += res.getInt("majorminor1");
                N2_Aa += res.getInt("majorminor2");

            }
            int N = N1_AA + N2_AA + N1_aA + N2_aA + N1_Aa + N2_Aa + N1_aa + N2_aa;
            //printf("%d \n", N);

            //3. find the frequencies P_AB, P_Ab, P_aB, P_ab.
            float P_AB = (float) (N1_AA + N2_AA) / N;
            float P_Ab = (float) (N1_AA + N2_aa) / N;
            float P_aB = (float) (N1_aa + N2_AA) / N;
            float P_ab = (float) (N1_aa + N2_aa) / N;

            float D = P_AB * P_ab - P_aB * P_Ab;
            //printf("%f \n", D);

            //5. P_A = P_AB + P_Ab, P_a = BigInteger.one - P_A
            //   P_B = P_AB + P_aB, P_b = BigInteger.one - P_B
            float P_A = P_AB + P_Ab;
            float P_B = P_AB + P_aB;

            //printf("%f %f \n", P_A, P_B);
            //6. If D>0, D_max = min(P_A*P_b, P_a*P_B)
            //	 else,   D_max = min(P_A*P_B, P_a*P_b)
            float D_max;
            if (D > 0) {
                D_max = Math.min(P_A * (1 - P_B), (1 - P_A) * P_B);
                //printf("greater than 0 \n");
            } else {
                D_max = Math.min(P_A * P_B, (1 - P_A) * (1 - P_B));
                //printf("not greater than 0 \n");
            }

            researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                    .add("type", "query_results")
                    .add("query", 0)//LD
                    .add("security", 0)//0 for plaintext
                    .add("D_max", D_max)
                    .build()
                    .toString());
        } else {
            System.out.println("sending result");
            Paillier paillier = new Paillier(true);
            BigInteger N1_AA = paillier.Encryption(BigInteger.ZERO), N1_Aa = paillier.Encryption(BigInteger.ZERO), N1_aA = paillier.Encryption(BigInteger.ZERO), N1_aa = paillier.Encryption(BigInteger.ZERO),
                    N2_AA = paillier.Encryption(BigInteger.ZERO), N2_Aa = paillier.Encryption(BigInteger.ZERO), N2_aA = paillier.Encryption(BigInteger.ZERO), N2_aa = paillier.Encryption(BigInteger.ZERO);
            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N1_AA = paillier.add(N1_AA, new BigInteger(res.getString("majormajor1")));
                N2_AA = paillier.add(N2_AA, new BigInteger(res.getString("majormajor2")));
                N1_aA = paillier.add(N1_aA, new BigInteger(res.getString("minormajor1")));
                N2_aA = paillier.add(N2_aA, new BigInteger(res.getString("minormajor2")));
                N1_aa = paillier.add(N1_aa, new BigInteger(res.getString("minorminor1")));
                N2_aa = paillier.add(N2_aa, new BigInteger(res.getString("minorminor2")));
                N1_Aa = paillier.add(N1_Aa, new BigInteger(res.getString("majorminor1")));
                N2_Aa = paillier.add(N2_Aa, new BigInteger(res.getString("majorminor2")));
            }
            BigInteger N_AB = paillier.add(N1_AA, N2_AA); 
            BigInteger N_Ab = paillier.add(N1_AA, N2_aa);
            BigInteger N_aB = paillier.add(N1_aa, N2_AA);
            BigInteger N_ab = paillier.add(N1_aa, N2_aa);
//            System.out.println(" Application1.exe 0 "
//                    + N_AB + " " + N_Ab + " " + N_aB + " " + N_ab);
            String output = executeConsoleCommand(" Application1.exe 0 "
                    + N_AB + " " + N_Ab + " " + N_aB + " " + N_ab, new File("C:\\Sadat\\MProjects\\gwas\\Enclave1\\Debug"));
            System.out.println("encalve out " + output);
            if (researcher.isOpen()) {
                researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query", 0)//LD
                        .add("security", 0)//0 for plaintext
                        .add("D_max", output)
                        .build()
                        .toString());      
            }      
        }
    }

    private void processHWE(int secure) throws IOException {
        if (secure == 0) {
            int N1_AA = 0, N1_Aa = 0, N1_aa = 0;
            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N1_AA += res.getInt("majormajor1");
                N1_aa += res.getInt("minorminor1");
                N1_Aa += res.getInt("majorminor1");

            }

            int N = N1_AA + N1_Aa + N1_aa;

            //step 2. P_A = (n_AA/n)+(0.5*(n_Aa/n))  Then, P_a = 1 - P_A
            double P_A = (double) (N1_AA / N) + (double) (0.5 * (N1_Aa / N));
            double P_a = 1.0 - P_A;
            //printf("%f %f \n", P_A, P_a);

            //step 3. Expected counts of AA= nP_A^2, Aa=2*nP_AP_a, aa=nP_a^2
            double N_AA_exp = N * P_A * P_A;
            double N_Aa_exp = 2 * N * P_A * P_a;
            double N_aa_exp = N * P_a * P_a;

            //step 4. Pearson goodness of fit test 
            double chi_square = (Math.pow((N1_AA - N_AA_exp), 2) / N_AA_exp) + (Math.pow((N1_Aa - N_Aa_exp), 2) / N_Aa_exp) + (Math.pow((N1_aa - N_aa_exp), 2) / N_aa_exp);

            researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                    .add("type", "query_results")
                    .add("query", 0)//LD
                    .add("security", 0)//0 for plaintext
                    .add("result", (chi_square >= 3.841) ? "0" : "1")
                    .build()
                    .toString());

        } else {//encrypted
            Paillier paillier = new Paillier(true);
            BigInteger N1_AA = paillier.Encryption(BigInteger.ZERO), N1_Aa = paillier.Encryption(BigInteger.ZERO), N1_aA = paillier.Encryption(BigInteger.ZERO), N1_aa = paillier.Encryption(BigInteger.ZERO);

            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N1_AA = paillier.add(N1_AA, new BigInteger(res.getString("majormajor1")));
                N1_aA = paillier.add(N1_aA, new BigInteger(res.getString("minormajor1")));
                N1_aa = paillier.add(N1_aa, new BigInteger(res.getString("minorminor1")));
                N1_Aa = paillier.add(N1_Aa, new BigInteger(res.getString("majorminor1")));
            }
            N1_Aa = paillier.add(N1_Aa, N1_aA);
            //enclave call
            String output = executeConsoleCommand("Application1.exe 1 "
                    + N1_AA + " " + N1_Aa + " " + N1_aa, new File("C:\\Sadat\\MProjects\\gwas\\Enclave1\\Debug\\"));
            System.out.println("encalve out " + output);
            if (researcher.isOpen()) {
                researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query", 1)//HWE
                        .add("security", 1)//0 for plaintext
                        .add("result", output)
                        .build()  
                        .toString());
            }
        }

    }

    private void processCATT(int secure) throws IOException {
        if (secure == 0) {
            int N_AA_case_d = 0, N_Aa_case_d = 0, N_aA_case_d = 0, N_aa_case_d = 0;
            int N_AA_control_d = 0, N_Aa_control_d = 0, N_aA_control_d = 0, N_aa_control_d = 0;

            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N_AA_case_d += res.getInt("majormajorCase");
                N_Aa_case_d += res.getInt("majorminorCase");
                N_aa_case_d += res.getInt("minorminorCase");
                N_aA_case_d += res.getInt("minormajorCase");

                N_AA_control_d += res.getInt("majormajorControl");
                N_Aa_control_d += res.getInt("majorminorControl");
                N_aa_control_d += res.getInt("minorminorControl");
                N_aA_control_d += res.getInt("minormajorControl");
            }

            //printf("%d \n", N_aa_case_d);
            int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

            int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
            int sum = case_sum + control_sum;

            //codominant model (0,1,2) 
            double weight1 = 0.0;
            double weight2 = 1.0;
            double weight3 = 2.0;

            double T = weight1 * (N_AA_control_d * case_sum - N_AA_case_d * control_sum)
                    + weight2 * (N_Aa_control_d * case_sum - N_Aa_case_d * control_sum)
                    + weight3 * (N_aa_control_d * case_sum - N_aa_case_d * control_sum);

            int AA_sum = N_AA_case_d + N_AA_control_d;
            int Aa_sum = N_Aa_case_d + N_Aa_control_d;
            int aa_sum = N_aa_case_d + N_aa_control_d;

            double var_T = ((control_sum * case_sum) / (double) (control_sum + case_sum))
                    * (((weight1 * weight1) * (sum - AA_sum) * AA_sum
                    + (weight2 * weight2) * (sum - Aa_sum) * Aa_sum
                    + (weight3 * weight3) * (sum - aa_sum) * aa_sum)
                    - (2 * ((Math.pow(weight1, 2) * Math.pow(weight2, 2) * AA_sum * Aa_sum) + ((Math.pow(weight2, 2) * Math.pow(weight2, 2) * Aa_sum * aa_sum)))));
            double chi_square = (T * T) / var_T;

            researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                    .add("type", "query_results")
                    .add("query", 0)//LD
                    .add("security", 0)//0 for plaintext
                    .add("result", (chi_square >= 3.841) ? "0" : "1")
                    .build()
                    .toString());

        } else {//encrypted
            Paillier paillier = new Paillier(true);
            BigInteger N_AA_case_d = BigInteger.ZERO, N_Aa_case_d = BigInteger.ZERO,
                    N_aA_case_d = BigInteger.ZERO, N_aa_case_d = BigInteger.ZERO;
            BigInteger N_AA_control_d = BigInteger.ZERO, N_Aa_control_d = BigInteger.ZERO,
                    N_aA_control_d = BigInteger.ZERO, N_aa_control_d = BigInteger.ZERO;
//            BigInteger N1_AA = paillier.Encryption(BigInteger.ZERO), N1_Aa = paillier.Encryption(BigInteger.ZERO), N1_aA = paillier.Encryption(BigInteger.ZERO), N1_aa = paillier.Encryption(BigInteger.ZERO);

            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                if (N_AA_case_d != BigInteger.ZERO) {
                    N_AA_case_d = paillier.add(N_AA_case_d, new BigInteger(res.getString("majormajorCase")));
                } else {
                    N_AA_case_d = new BigInteger(res.getString("majormajorCase"));
                }

                if (N_Aa_case_d != BigInteger.ZERO) {
                    N_Aa_case_d = paillier.add(N_Aa_case_d, new BigInteger(res.getString("majorminorCase")));
                } else {
                    N_Aa_case_d = new BigInteger(res.getString("majorminorCase"));
                }
                N_Aa_case_d = paillier.add(N_Aa_case_d, new BigInteger(res.getString("minormajorCase")));

                if (N_aa_case_d != BigInteger.ZERO) {
                    N_aa_case_d = paillier.add(N_aa_case_d, new BigInteger(res.getString("minorminorCase")));
                } else {
                    N_aa_case_d = new BigInteger(res.getString("minorminorCase"));
                }

                if (N_AA_control_d != BigInteger.ZERO) {
                    N_AA_control_d = paillier.add(N_AA_control_d, new BigInteger(res.getString("majormajorControl")));
                } else {
                    N_AA_control_d = new BigInteger(res.getString("majormajorControl"));
                }

                if (N_Aa_control_d != BigInteger.ZERO) {
                    N_Aa_control_d = paillier.add(N_Aa_control_d, new BigInteger(res.getString("majorminorControl")));
                } else {
                    N_Aa_control_d = new BigInteger(res.getString("majorminorControl"));
                }
                N_Aa_control_d = paillier.add(N_Aa_control_d, new BigInteger(res.getString("minormajorControl")));

                if (N_aa_control_d != BigInteger.ZERO) {
                    N_aa_control_d = paillier.add(N_aa_control_d, new BigInteger(res.getString("minorminorControl")));
                } else {
                    N_aa_control_d = new BigInteger(res.getString("minorminorControl"));
                }
            }
//            N1_Aa = paillier.add(N1_Aa, N1_aA);
            //enclave call

            String output = executeConsoleCommand(" Application1.exe 2 "
                    + N_AA_case_d + " " + N_Aa_case_d + " " + N_aa_case_d + " "
                    + N_AA_control_d + " " + N_Aa_control_d + " " + N_aa_control_d, new File("C:\\Sadat\\MProjects\\gwas\\Enclave1\\Debug"));
//            System.out.println("encalve out " + output);
            if (researcher.isOpen()) {
                researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query", 2)//CATT
                        .add("security", 1)//0 for plaintext
                        .add("result", output)
                        .build()
                        .toString());
            }

        }

    }

    private void processFET(int secure) throws IOException {
        if (secure == 0) {
            int N_AA_case_d = 0, N_Aa_case_d = 0, N_aA_case_d = 0, N_aa_case_d = 0;
            int N_AA_control_d = 0, N_Aa_control_d = 0, N_aA_control_d = 0, N_aa_control_d = 0;

            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                N_AA_case_d += res.getInt("majormajorCase");
                N_Aa_case_d += res.getInt("majorminorCase");
                N_aa_case_d += res.getInt("minorminorCase");
                N_aA_case_d += res.getInt("minormajorCase");

                N_AA_control_d += res.getInt("majormajorControl");
                N_Aa_control_d += res.getInt("majorminorControl");
                N_aa_control_d += res.getInt("minorminorControl");
                N_aA_control_d += res.getInt("minormajorControl");
            }

            int case_sum = N_AA_case_d + N_Aa_case_d + N_aa_case_d;

            int control_sum = N_AA_control_d + N_Aa_control_d + N_aa_control_d;
            int sum = case_sum + control_sum;

            int AA_sum = N_AA_case_d + N_AA_control_d;
            int Aa_sum = N_Aa_case_d + N_Aa_control_d;
            int aa_sum = N_aa_case_d + N_aa_control_d;

            //int lob = factorial(case_sum)*factorial(control_sum) * factorial(AA_sum) * factorial(Aa_sum) * factorial(aa_sum);
            //int hor = factorial(N_AA_control_d) * factorial(N_Aa _control_d) * factorial(N_aa_control_d) * factorial(N_AA_case_d) * factorial(N_Aa_case_d) * factorial(N_aa_case_d) * factorial(sum);
//            int denominator = factorial(5) * factorial(4) * factorial(3) * factorial(3) * factorial(3);
//            int numerator = factorial(1) * factorial(2) * factorial(2) * factorial(2) * factorial(1) * factorial(1) * factorial(19);
            //float p_value = fisher23(70,20,10,40,30,30,0);  //denominator/(float)numerator;
            //float p_value = fisher23(0,3,2,6,5,1,0);
            double p_value = new FisherTest().fisher23(N_AA_control_d, N_Aa_control_d, N_aa_control_d, N_AA_case_d, N_Aa_case_d, N_aa_case_d, 0);

            researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                    .add("type", "query_results")
                    .add("query", 3)//FET
                    .add("security", 0)//0 for plaintext
                    .add("result", (p_value >= 0.05) ? "0" : "1")
                    .build()
                    .toString());
        } else {
            BigInteger N_AA_case_d = BigInteger.ZERO, N_Aa_case_d = BigInteger.ZERO,
                    N_aA_case_d = BigInteger.ZERO, N_aa_case_d = BigInteger.ZERO;
            BigInteger N_AA_control_d = BigInteger.ZERO, N_Aa_control_d = BigInteger.ZERO,
                    N_aA_control_d = BigInteger.ZERO, N_aa_control_d = BigInteger.ZERO;
            Paillier paillier = new Paillier(true);

            for (Map.Entry<String, String> entrySet : sentQueries.entrySet()) {
                JsonObject res = Json.createReader(new StringReader(entrySet.getValue())).readObject();
                if (N_AA_case_d != BigInteger.ZERO) {
                    N_AA_case_d = paillier.add(N_AA_case_d, new BigInteger(res.getString("majormajorCase")));
                } else {
                    N_AA_case_d = new BigInteger(res.getString("majormajorCase"));
                }

                if (N_Aa_case_d != BigInteger.ZERO) {
                    N_Aa_case_d = paillier.add(N_Aa_case_d, new BigInteger(res.getString("majorminorCase")));
                } else {
                    N_Aa_case_d = new BigInteger(res.getString("majorminorCase"));
                }
                N_Aa_case_d = paillier.add(N_Aa_case_d, new BigInteger(res.getString("minormajorCase")));

                if (N_aa_case_d != BigInteger.ZERO) {
                    N_aa_case_d = paillier.add(N_aa_case_d, new BigInteger(res.getString("minorminorCase")));
                } else {
                    N_aa_case_d = new BigInteger(res.getString("minorminorCase"));
                }

                if (N_AA_control_d != BigInteger.ZERO) {
                    N_AA_control_d = paillier.add(N_AA_control_d, new BigInteger(res.getString("majormajorControl")));
                } else {
                    N_AA_control_d = new BigInteger(res.getString("majormajorControl"));
                }

                if (N_Aa_control_d != BigInteger.ZERO) {
                    N_Aa_control_d = paillier.add(N_Aa_control_d, new BigInteger(res.getString("majorminorControl")));
                } else {
                    N_Aa_control_d = new BigInteger(res.getString("majorminorControl"));
                }
                N_Aa_control_d = paillier.add(N_Aa_control_d, new BigInteger(res.getString("minormajorControl")));

                if (N_aa_control_d != BigInteger.ZERO) {
                    N_aa_control_d = paillier.add(N_aa_control_d, new BigInteger(res.getString("minorminorControl")));
                } else {
                    N_aa_control_d = new BigInteger(res.getString("minorminorControl"));
                }
            }
//            N1_Aa = paillier.add(N1_Aa, N1_aA);
            String output = executeConsoleCommand(" Application1.exe 3 "
                    + N_AA_case_d + " " + N_Aa_case_d + " " + N_aa_case_d + " "
                    + N_AA_control_d + " " + N_Aa_control_d + " " + N_aa_control_d, new File("C:\\Sadat\\MProjects\\gwas\\Enclave1\\Debug"));
//            System.out.println("encalve out " + output);
            if (researcher.isOpen()) {
                researcher.getBasicRemote().sendText(Json.createObjectBuilder()
                        .add("type", "query_results")
                        .add("query", 3)//FET
                        .add("security", 1)//0 for plaintext
                        .add("result", output)
                        .build()
                        .toString());
            }

        }
    }

    private static class DataOwner {

        public int id = 0;
        public Session session;
        public boolean active = false;

        public DataOwner(Session session) {
            this.session = session;
            id = new Random().nextInt(10000);
            System.out.println("addedd " + id);
            active = true;
        }
    }
}
