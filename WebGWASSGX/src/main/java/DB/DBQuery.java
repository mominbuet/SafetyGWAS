/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DB;

import java.util.ArrayList;
import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;

/**
 *
 * @author azizmma
 */
public class DBQuery {

    String opuname = "cs.umanitoba.ca_WebGWASSGX_war_1.0.0PU";

    public GwasPlaintext getFromSnip(String snip) {
        GwasPlaintext res = null;
        try {
            EntityManagerFactory emf = Persistence.createEntityManagerFactory(opuname);
            EntityManager em = emf.createEntityManager();
            res = em.createNamedQuery("GwasPlaintext.findBySnpid", GwasPlaintext.class)
                    .setParameter("snpid", snip).setMaxResults(1).getResultList().get(0);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    public GwasPlaintext getFromSnip(String snip, int casecontrol) {
        GwasPlaintext res = null;
        try {
            EntityManagerFactory emf = Persistence.createEntityManagerFactory(opuname);
            EntityManager em = emf.createEntityManager();
            res = em.createNamedQuery("GwasPlaintext.findBySnpidCasecontrol", GwasPlaintext.class)
                    .setParameter("snpid", snip)
                    .setParameter("casecontrol", casecontrol)
                    .setMaxResults(1).getResultList().get(0);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    public GwasEncrypted getFromSnipEnc(String snip, int casecontrol) {
        GwasEncrypted res = null;
        try {
            EntityManagerFactory emf = Persistence.createEntityManagerFactory(opuname);
            EntityManager em = emf.createEntityManager();
            res = em.createNamedQuery("GwasEncrypted.findBySnpidCasecontrol", GwasEncrypted.class)
                    .setParameter("snpid", snip)
                    .setParameter("casecontrol", casecontrol)
                    .setMaxResults(1).getResultList().get(0);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    public GwasEncrypted getFromSnipEnc(String snip) {
        GwasEncrypted res = null;
        try {
            EntityManagerFactory emf = Persistence.createEntityManagerFactory(opuname);
            EntityManager em = emf.createEntityManager();
            res = em.createNamedQuery("GwasEncrypted.findBySnpid", GwasEncrypted.class)
                    .setParameter("snpid", snip).setMaxResults(1).getResultList().get(0);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return res;
    }

    public <T> T insertGeneric(T p) {
        try {
            EntityManagerFactory emf = Persistence.createEntityManagerFactory(opuname);
            EntityManager em = emf.createEntityManager();
            EntityTransaction entr = em.getTransaction();
            entr.begin();
            em.persist(p);
            entr.commit();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return p;
    }

}
