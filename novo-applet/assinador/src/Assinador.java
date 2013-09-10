
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import javax.security.auth.login.LoginException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.table.DefaultTableModel;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import netscape.javascript.JSException;
import netscape.javascript.JSObject;
import sun.security.pkcs11.SunPKCS11;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author marcio.figueiredo
 */
public class Assinador extends javax.swing.JApplet {

    private static final int TAB_CERTIFICADO = 0;
    private static final int TAB_STATUS = 1;
    private static final String DRIVERS_WIN = "windows.drivers";
    private static final String DRIVERS_MAC = "mac.drivers";
    private static final String DRIVERS_LNX = "linux.drivers";

    /**
     * Initializes the applet Assinador
     */
    @Override
    public void init() {
        try {
            // Set cross-platform Java L&F (also called "Metal")
            UIManager.setLookAndFeel("javax.swing.plaf.metal.MetalLookAndFeel");
        } catch (UnsupportedLookAndFeelException e) {
        } catch (ClassNotFoundException e) {
        } catch (InstantiationException e) {
        } catch (IllegalAccessException e) {
        }

        /* Create and display the applet */
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable() {
                public void run() {
                    initComponents();
                    PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
                    try {
                        initialize();
                    } catch (LoginException ex) {
                        tabs.setSelectedIndex(TAB_STATUS);
                        ex.printStackTrace(writter);
                    } catch (KeyStoreException ex) {
                        tabs.setSelectedIndex(TAB_STATUS);
                        ex.printStackTrace(writter);
                    } catch (Exception ex) {
                        tabs.setSelectedIndex(TAB_STATUS);
                        jTextArea1.append(ex.getMessage());
                        btProcurarDriver.setEnabled(true);
                    }
                }
            });
            btProcurarDriver.setEnabled(false);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    // Implementações Márcio 27/08/2013

    private KeyStore ksEntry() throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = null;
        if (getOs().contains("Windows")) {
            ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, null);
        } else {
            ks = KeyStore.getInstance("PKCS11");
            String senha = JOptionPane.showInputDialog("Digite a senha do certificado:");
            if (!"".equals(senha)) {
                ks.load(null, senha.toCharArray());
            }
        }
        return ks;
    }

    private void getProviderCert(File driverCert) throws LoginException, FileNotFoundException, IOException {
        Provider p = null;
        AuthProvider ap = null;
        p = new SunPKCS11(new ByteArrayInputStream(new String("name = SafeWeb" + "\n" + "library =  " + driverCert.getAbsolutePath() + "\n" + "showInfo = true").getBytes()));
        ap = (AuthProvider) p;
        ap.logout();
        Security.addProvider(p);
    }

    private String getOs() {
        return System.getProperties().getProperty("os.name");
    }

    private void populateTreeCertificados() throws KeyStoreException, LoginException, CertificateParsingException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, Exception {
        findDriverCerticate();
        KeyStore ks = null;
        try {
            ks = ksEntry();
        } catch (KeyStoreException ex) {
            btProcurarDriver.setEnabled(true);
            tabs.setSelectedIndex(TAB_STATUS);
            throw new Exception("Não foi possível localizar o certificado. Selecione o driver correspondente ao SmartCard/Token e tente novamente.");
        }
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        IcpBrasilUtils icpBrasil = new IcpBrasilUtils();
        X509Certificate certificate;
        Collection<Certificados> certList = null;
        for (Enumeration<String> enumKs = ks.aliases(); enumKs.hasMoreElements();) {
            String alias = enumKs.nextElement().toString();
            certificate = (X509Certificate) ks.getCertificate(alias);
            if (!icpBrasil.isFinalCertificate(certificate)) {
                String name = icpBrasil.getNome(certificate.getSubjectX500Principal());
                String entidadeCertificadora = icpBrasil.getEntidadeCertificadora(certificate
                        .getSubjectX500Principal());
                if (entidadeCertificadora.contains("ICP-Brasil")) {
                    if (certList == null) {
                        certList = new ArrayList<Certificados>();
                    }
                    Certificados cert = new Certificados();
                    cert.setCertificado(certificate);
                    cert.setChecked(false);
                    cert.setEmitidoPara(name);
                    cert.setEmitidoPor(icpBrasil.getNome(certificate.getIssuerX500Principal()));
                    cert.setEntidade(icpBrasil.getEntidadeCertificadora(certificate
                            .getIssuerX500Principal()));
                    cert.setValidoAte(sdf.format(certificate.getNotAfter()));
                    certList.add(cert);
                }
            }
        }
        setCertModel(certList);
        if (certList == null || certList.isEmpty()) {
            btProcurarDriver.setEnabled(true);
        }
    }

    private void setCertModel(Collection<Certificados> certList) {
        certModel = new DefaultTableModel() {
            @Override
            public Class getColumnClass(int c) {
                return getValueAt(0, c).getClass();
            }

            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return false;
            }
        };
        certModel.addColumn("Emitido para");
        certModel.addColumn("Emitido por");
        certModel.addColumn("Válido até");

        for (Certificados c : certList) {
            Object[] linha = new Object[3];
            linha[0] = c.getEmitidoPara();
            linha[1] = c.getEmitidoPor();
            linha[2] = c.getValidoAte();
            certModel.addRow(linha);
        }
        jTable1.setModel(certModel);
        jTable1.getColumnModel().getColumn(0).setPreferredWidth(380);
        jTable1.getColumnModel().getColumn(1).setPreferredWidth(100);
        jTable1.getColumnModel().getColumn(2).setPreferredWidth(50);
    }

    private void initializeBrowser() {
        if (browserWindow == null) {
            browserWindow = netscape.javascript.JSObject.getWindow(this);
        }
        if (mainForm == null) {
            mainForm = (JSObject) browserWindow.eval("document.forms[2]");
        }
    }

    private void executeJspButton() {
        executeJspButton("saveNFE");
    }

    private void executeJspButton(String name) {
        initializeBrowser();
        browserWindow.call(name, null);
    }

    private String getDate() {
        Date dataAtual = new Date();
        SimpleDateFormat spf = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
        return spf.format(dataAtual);
    }

    private String getJSObject(String fieldName) {
        initializeBrowser();
        JSObject object = (JSObject) mainForm.getMember(fieldName);
        if (object == null) {
            return null;
        }
        String value;
        try {
            value = URLDecoder.decode((String) object.getMember("value"), "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            JOptionPane.showMessageDialog(this, e.getMessage());
            return null;
        } catch (JSException e) {
            JOptionPane.showMessageDialog(this, e.getMessage());
            return null;
        }
        return value;
    }

    private Object[] getParameters() {
        Object[] params = new Object[4];
        params[0] = getJSObject("mainForm:p1");
        params[1] = getJSObject("mainForm:p2");
        params[2] = getJSObject("mainForm:p3");
        params[3] = getJSObject("mainForm:p4");
        return params;
    }

    private String getUrlReport() {
        return getJSObject("mainForm:returnUrl");
    }

    private String getXml() {
        if (xml == null) {
            xml = getJSObject("mainForm:xml");
        }
        return xml;
    }

    private void findDriverCerticate() throws FileNotFoundException, IOException, LoginException {
        if (getOs().contains("Windows")) {
            readArqDrivers(DRIVERS_WIN);
        } else if (getOs().contains("Linux")) {
            readArqDrivers(DRIVERS_LNX);
        } else if (getOs().contains("Mac")) {
            readArqDrivers(DRIVERS_MAC);
        } else {
            throw new IOException("Não foi possível determinar o Sistema Operacional");
        }
    }

    private void readArqDrivers(String name) throws IOException, LoginException {
        BufferedReader in = new BufferedReader(new FileReader(getClass().getResource(name).getFile()));
        String str;
        while (in.ready()) {
            str = in.readLine();
            File driverRead = new File(str);
            if (driverRead.exists()) {
                try {
                    getProviderCert(driverRead);
                } catch (ProviderException ex) {
                    continue;
                }
                break;
            }
        }
        in.close();
    }

    private void initialize() throws LoginException, KeyStoreException, Exception {
        populateTreeCertificados();
        xml = getParameter("xml");
        tagAssinar = getParameter("tagAssinar");
        btProcurarDriver.addActionListener(
                new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                driver = new JFileChooser();
                int returnValue = driver.showOpenDialog(null);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = driver.getSelectedFile();
                    jTextArea1.append("Arquivo selecionado: " + selectedFile.getPath() + "\r\n");
                }
            }
        });
    }

    private void assinar() {
        // Pega o tipo de documento que quer assinar
        String type = getParameter("typeSign");

        // Instancia a classe para escrever no JTextArea
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        writter.append("[" + getDate() + "] Iniciando o processo de assinatura digital");

        if ("PDF".equalsIgnoreCase(type)) {
            executeJspButton("processReport");
        }
        
        
        
        // Fecha a popup
        if ("PDF".equalsIgnoreCase(type)) {
            executeJspButton("closePopupApplet");
        } else {
            executeJspButton("closePopup");
        }

    }

    /**
     * This method is called from within the init() method to initialize the
     * form. WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel3 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        tabs = new javax.swing.JTabbedPane();
        tabCertificados = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        jButton2 = new javax.swing.JButton();
        btProcurarDriver = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        tabStatus = new javax.swing.JPanel();
        btVoltar = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jProgressBar1 = new javax.swing.JProgressBar();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel3 = new javax.swing.JLabel();

        setMaximumSize(new java.awt.Dimension(655, 335));
        setMinimumSize(new java.awt.Dimension(655, 335));

        jPanel3.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jPanel3.setMinimumSize(new java.awt.Dimension(655, 335));
        jPanel3.setPreferredSize(new java.awt.Dimension(655, 335));

        jLabel1.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        jLabel1.setText("Assinar nota fiscal");

        jLabel2.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jLabel2.setText("Versão: 2.0.00");

        tabCertificados.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N

        jTable1.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        jTable1.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane1.setViewportView(jTable1);
        jTable1.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

        jButton2.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jButton2.setIcon(new javax.swing.ImageIcon(getClass().getResource("/sign.png"))); // NOI18N
        jButton2.setText("Assinar");
        jButton2.setToolTipText("Efetuar assinatura");

        btProcurarDriver.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        btProcurarDriver.setIcon(new javax.swing.ImageIcon(getClass().getResource("/search.png"))); // NOI18N
        btProcurarDriver.setText("Procurar driver do dispositivo");
        btProcurarDriver.setToolTipText("Localizar driver Linux/Mac");

        jButton1.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jButton1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/arrow-refresh.png"))); // NOI18N
        jButton1.setToolTipText("Recarregar certificados");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout tabCertificadosLayout = new javax.swing.GroupLayout(tabCertificados);
        tabCertificados.setLayout(tabCertificadosLayout);
        tabCertificadosLayout.setHorizontalGroup(
            tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabCertificadosLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 610, Short.MAX_VALUE)
                    .addGroup(tabCertificadosLayout.createSequentialGroup()
                        .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(btProcurarDriver)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        tabCertificadosLayout.setVerticalGroup(
            tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabCertificadosLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 186, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButton2)
                    .addComponent(btProcurarDriver)
                    .addComponent(jButton1))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tabs.addTab("Certificados", new javax.swing.ImageIcon(getClass().getResource("/certificates.png")), tabCertificados); // NOI18N

        tabStatus.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N

        btVoltar.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        btVoltar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/back.png"))); // NOI18N
        btVoltar.setText("Voltar");
        btVoltar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btVoltarActionPerformed(evt);
            }
        });

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jTextArea1.setRows(5);
        jScrollPane2.setViewportView(jTextArea1);

        javax.swing.GroupLayout tabStatusLayout = new javax.swing.GroupLayout(tabStatus);
        tabStatus.setLayout(tabStatusLayout);
        tabStatusLayout.setHorizontalGroup(
            tabStatusLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabStatusLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(tabStatusLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jProgressBar1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabStatusLayout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(btVoltar))
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 610, Short.MAX_VALUE))
                .addContainerGap())
        );
        tabStatusLayout.setVerticalGroup(
            tabStatusLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, tabStatusLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 160, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jProgressBar1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(12, 12, 12)
                .addComponent(btVoltar)
                .addContainerGap())
        );

        tabs.addTab("Status", new javax.swing.ImageIcon(getClass().getResource("/process.png")), tabStatus); // NOI18N

        jLabel3.setIcon(new javax.swing.ImageIcon(getClass().getResource("/security-high.png"))); // NOI18N

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(jLabel3)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel1)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel2))
                    .addComponent(tabs)
                    .addComponent(jSeparator1))
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addComponent(jLabel2))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel3))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabel1)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 3, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tabs, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
    }// </editor-fold>//GEN-END:initComponents

    private void btVoltarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btVoltarActionPerformed
        tabs.setSelectedIndex(TAB_CERTIFICADO);
    }//GEN-LAST:event_btVoltarActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        try {
            populateTreeCertificados();
        } catch (KeyStoreException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (LoginException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (CertificateParsingException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (NoSuchProviderException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (IOException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (NoSuchAlgorithmException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (CertificateException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace(writter);
        } catch (Exception ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            jTextArea1.append(ex.getMessage());
            btProcurarDriver.setEnabled(true);
        }
    }//GEN-LAST:event_jButton1ActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btProcurarDriver;
    private javax.swing.JButton btVoltar;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTable jTable1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JPanel tabCertificados;
    private javax.swing.JPanel tabStatus;
    private javax.swing.JTabbedPane tabs;
    // End of variables declaration//GEN-END:variables
    private DefaultTableModel certModel;
    private JSObject browserWindow;
    private JSObject mainForm;
    private String xml;
    private String tagAssinar;
    private JFileChooser driver;
    private String aliasCert;
    private Certificate[] certificate;
    private KeyInfo keyInfo;
    private PrivateKey privateKey;
}
