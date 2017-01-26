/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package DB;

import java.io.Serializable;
import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author azizmma
 */
@Entity
@Table(name = "gwas_plaintext")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "GwasPlaintext.findAll", query = "SELECT g FROM GwasPlaintext g"),
    @NamedQuery(name = "GwasPlaintext.findById", query = "SELECT g FROM GwasPlaintext g WHERE g.id = :id"),
    @NamedQuery(name = "GwasPlaintext.findBySnpid", query = "SELECT g FROM GwasPlaintext g WHERE g.snpid = :snpid"),
    @NamedQuery(name = "GwasPlaintext.findBySnpidCasecontrol", query = "SELECT g FROM GwasPlaintext g WHERE g.snpid = :snpid and g.casecontrol = :casecontrol"),
    @NamedQuery(name = "GwasPlaintext.findByCasecontrol", query = "SELECT g FROM GwasPlaintext g WHERE g.casecontrol = :casecontrol"),
    @NamedQuery(name = "GwasPlaintext.findByMajormajor", query = "SELECT g FROM GwasPlaintext g WHERE g.majormajor = :majormajor"),
    @NamedQuery(name = "GwasPlaintext.findByMajorminor", query = "SELECT g FROM GwasPlaintext g WHERE g.majorminor = :majorminor"),
    @NamedQuery(name = "GwasPlaintext.findByMinormajor", query = "SELECT g FROM GwasPlaintext g WHERE g.minormajor = :minormajor"),
    @NamedQuery(name = "GwasPlaintext.findByMinorminor", query = "SELECT g FROM GwasPlaintext g WHERE g.minorminor = :minorminor"),
    @NamedQuery(name = "GwasPlaintext.findByUpdated", query = "SELECT g FROM GwasPlaintext g WHERE g.updated = :updated")})
public class GwasPlaintext implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id")
    private Integer id;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 50)
    @Column(name = "snpid")
    private String snpid;
    @Basic(optional = false)
    @NotNull
    @Column(name = "casecontrol")
    private int casecontrol;
    @Basic(optional = false)
    @NotNull
    @Column(name = "majormajor")
    private int majormajor;
    @Basic(optional = false)
    @NotNull
    @Column(name = "majorminor")
    private int majorminor;
    @Basic(optional = false)
    @NotNull
    @Column(name = "minormajor")
    private int minormajor;
    @Basic(optional = false)
    @NotNull
    @Column(name = "minorminor")
    private int minorminor;
    @Basic(optional = false)
    @NotNull
    @Column(name = "updated")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updated;

    public GwasPlaintext() {
    }

    public GwasPlaintext(Integer id) {
        this.id = id;
    }

    public GwasPlaintext(Integer id, String snpid, int casecontrol, int majormajor, int majorminor, int minormajor, int minorminor, Date updated) {
        this.id = id;
        this.snpid = snpid;
        this.casecontrol = casecontrol;
        this.majormajor = majormajor;
        this.majorminor = majorminor;
        this.minormajor = minormajor;
        this.minorminor = minorminor;
        this.updated = updated;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getSnpid() {
        return snpid;
    }

    public void setSnpid(String snpid) {
        this.snpid = snpid;
    }

    public int getCasecontrol() {
        return casecontrol;
    }

    public void setCasecontrol(int casecontrol) {
        this.casecontrol = casecontrol;
    }

    public int getMajormajor() {
        return majormajor;
    }

    public void setMajormajor(int majormajor) {
        this.majormajor = majormajor;
    }

    public int getMajorminor() {
        return majorminor;
    }

    public void setMajorminor(int majorminor) {
        this.majorminor = majorminor;
    }

    public int getMinormajor() {
        return minormajor;
    }

    public void setMinormajor(int minormajor) {
        this.minormajor = minormajor;
    }

    public int getMinorminor() {
        return minorminor;
    }

    public void setMinorminor(int minorminor) {
        this.minorminor = minorminor;
    }

    public Date getUpdated() {
        return updated;
    }

    public void setUpdated(Date updated) {
        this.updated = updated;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (id != null ? id.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof GwasPlaintext)) {
            return false;
        }
        GwasPlaintext other = (GwasPlaintext) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "DB.GwasPlaintext[ id=" + id + " ]";
    }
    
}
