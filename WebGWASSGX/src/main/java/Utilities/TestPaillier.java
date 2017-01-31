/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utilities;

import java.math.BigInteger;
import java.util.Date;

/**
 *
 * @author azizmma
 */
public class TestPaillier {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
//        Paillier paillier = new Paillier(true);
//        BigInteger c1 = paillier.Encryption(BigInteger.ONE);
//        Date d1 = new Date();
//        BigInteger c2 = paillier.Decryption(c1);
//        System.out.println("diff "+(double)(new Date().getTime()-d1.getTime()));
        Paillier paillier = new Paillier();
        System.out.println("landa size " + paillier.getLambda().toString().length());
        paillier = new Paillier();
        System.out.println("landa size " + paillier.getLambda().toString().length());
        paillier = new Paillier();
        System.out.println("landa size " + paillier.getLambda().toString().length());
//        BigInteger c3  = paillier.add(c1, c2);

    }

}
