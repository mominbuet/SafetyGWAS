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
@Table(name = "gwas_encrypted")
@XmlRootElement
@NamedQueries({
    @NamedQuery(name = "GwasEncrypted.findAll", query = "SELECT g FROM GwasEncrypted g"),
    @NamedQuery(name = "GwasEncrypted.findById", query = "SELECT g FROM GwasEncrypted g WHERE g.id = :id"),
    @NamedQuery(name = "GwasEncrypted.findBySnpid", query = "SELECT g FROM GwasEncrypted g WHERE g.snpid = :snpid"),
    @NamedQuery(name = "GwasEncrypted.findBySnpidCasecontrol", query = "SELECT g FROM GwasEncrypted g WHERE g.snpid = :snpid and g.casecontrol = :casecontrol"),
    @NamedQuery(name = "GwasEncrypted.findByCasecontrol", query = "SELECT g FROM GwasEncrypted g WHERE g.casecontrol = :casecontrol"),
    @NamedQuery(name = "GwasEncrypted.findByMajormajor", query = "SELECT g FROM GwasEncrypted g WHERE g.majormajor = :majormajor"),
    @NamedQuery(name = "GwasEncrypted.findByMajorminor", query = "SELECT g FROM GwasEncrypted g WHERE g.majorminor = :majorminor"),
    @NamedQuery(name = "GwasEncrypted.findByMinormajor", query = "SELECT g FROM GwasEncrypted g WHERE g.minormajor = :minormajor"),
    @NamedQuery(name = "GwasEncrypted.findByMinorminor", query = "SELECT g FROM GwasEncrypted g WHERE g.minorminor = :minorminor"),
    @NamedQuery(name = "GwasEncrypted.findByUpdated", query = "SELECT g FROM GwasEncrypted g WHERE g.updated = :updated")})
public class GwasEncrypted implements Serializable {
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
    @Size(min = 1, max = 1000)
    @Column(name = "majormajor")
    private String majormajor;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 1000)
    @Column(name = "majorminor")
    private String majorminor;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 1000)
    @Column(name = "minormajor")
    private String minormajor;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 1000)
    @Column(name = "minorminor")
    private String minorminor;
    @Basic(optional = false)
    @NotNull
    @Column(name = "updated")
    @Temporal(TemporalType.TIMESTAMP)
    private Date updated;

    public GwasEncrypted() {
    }

    public GwasEncrypted(Integer id) {
        this.id = id;
    }

    public GwasEncrypted(Integer id, String snpid, int casecontrol, String majormajor, String majorminor, String minormajor, String minorminor, Date updated) {
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

    public String getMajormajor() {
        return majormajor;
    }

    public void setMajormajor(String majormajor) {
        this.majormajor = majormajor;
    }

    public String getMajorminor() {
        return majorminor;
    }

    public void setMajorminor(String majorminor) {
        this.majorminor = majorminor;
    }

    public String getMinormajor() {
        return minormajor;
    }

    public void setMinormajor(String minormajor) {
        this.minormajor = minormajor;
    }

    public String getMinorminor() {
        return minorminor;
    }

    public void setMinorminor(String minorminor) {
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
        if (!(object instanceof GwasEncrypted)) {
            return false;
        }
        GwasEncrypted other = (GwasEncrypted) object;
        if ((this.id == null && other.id != null) || (this.id != null && !this.id.equals(other.id))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "DB.GwasEncrypted[ id=" + id + " ]";
    }
    
}
