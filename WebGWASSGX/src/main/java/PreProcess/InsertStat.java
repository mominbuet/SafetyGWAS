/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PreProcess;

import DB.DBQuery;
import DB.GwasEncrypted;
import DB.GwasPlaintext;
import Utilities.Paillier;
import java.math.BigInteger;
import java.util.Date;
import java.util.Random;

/**
 *
 * @author azizmma
 */
public class InsertStat {

    static int rowcount = 1000;
    static int min = 1;
    static int max = 100;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Paillier paillier = new Paillier(true);
        DBQuery dbq = new DBQuery();
        for (int i = 0; i < rowcount; i++) {

            for (int j = 0; j < 2; j++) {//case control

                AlleleStats alleleStats = new AlleleStats();
                GwasPlaintext gwasPlaintext = new GwasPlaintext();
                gwasPlaintext.setCasecontrol(j);
                gwasPlaintext.setMajormajor(alleleStats.AA);
                gwasPlaintext.setMajorminor(alleleStats.Aa);
                gwasPlaintext.setMajorminor(alleleStats.Aa);
                gwasPlaintext.setMinormajor(alleleStats.Aa);
                gwasPlaintext.setMinorminor(alleleStats.aa);
                gwasPlaintext.setUpdated(new Date());
                gwasPlaintext.setSnpid("rs" + (int) 1000 + i);
                dbq.insertGeneric(gwasPlaintext);

                GwasEncrypted gwasEncrypted = new GwasEncrypted();
                gwasEncrypted.setCasecontrol(j);
                gwasEncrypted.setMajormajor(paillier.Encryption(new BigInteger("" + alleleStats.AA)).toString());
                gwasEncrypted.setMajorminor(paillier.Encryption(new BigInteger("" + alleleStats.Aa)).toString());
                gwasEncrypted.setMinormajor(paillier.Encryption(new BigInteger("" + alleleStats.Aa)).toString());
                gwasEncrypted.setMinorminor(paillier.Encryption(new BigInteger("" + alleleStats.aa)).toString());
                gwasEncrypted.setUpdated(new Date());
                gwasEncrypted.setSnpid("rs" + (int) 1000 + i);
                dbq.insertGeneric(gwasEncrypted);

            }
        }
    }

//    public static AlleleStats getStats() {
//        
//    }
    private static class AlleleStats {

        public int AA = 0, Aa = 0, aA = 0, aa = 0;

        public AlleleStats() {
            Random rand = new Random();
            this.AA = rand.nextInt(max) + min;
            this.Aa = rand.nextInt(max) + min;
            this.aA = rand.nextInt(max) + min;
            this.aa = rand.nextInt(max) + min;
        }
    }
}
