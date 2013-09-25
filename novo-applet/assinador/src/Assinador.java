
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import javax.security.auth.login.LoginException;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
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
    private static final int TAB_A1 = 1;
    private static final int TAB_STATUS = 2;
    private static final String DRIVERS_WIN = "windows.drivers";
    private static final String DRIVERS_MAC = "mac.drivers";
    private static final String DRIVERS_LNX = "linux.drivers";
    private static final String MSG_TIPO_ARQ_NOT_FOUND = "Não foi possível identificar o tipo do arquivo a ser assinado.";
    private static final String CERTIFICADOS_DATA = "certificadosData";

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
                    getTituloJanela();                    
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
                    }
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private void getTituloJanela(){
        String titulo = getParameter("tituloJanela");
        if(titulo != null && !titulo.isEmpty()){
            lblTituloJanela.setText(titulo);
        }
    }

    public Map<String, Object> getData() {
        if (data == null) {
            data = new LinkedHashMap<String, Object>();
        }
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }

    // Implementações Márcio 27/08/2013
    private void getProviderCert(File driverCert) throws LoginException, FileNotFoundException, IOException {
        provider = new SunPKCS11(new ByteArrayInputStream(new String("name = SafeWeb" + "\n" + "library =  " + driverCert.getAbsolutePath() + "\n" + "showInfo = true").getBytes()));
        AuthProvider ap = (AuthProvider) provider;
        ap.logout();
        Security.addProvider(provider);
    }

    private String getOs() {
        return System.getProperties().getProperty("os.name");
    }

    private String getHomeUser() {
        return System.getProperties().getProperty("user.home");
    }
    
    private KeyStore ksEntry() throws KeyStoreException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, LoginException {
        if (getOs().contains("Windows")) {
            ks = KeyStore.getInstance("Windows-MY");
            ks.load(null, null);
        } else {
            findDriverCerticate();
            ks = KeyStore.getInstance("PKCS11", provider);
            JLabel label = new JLabel("Digite a senha do certificado:");
            JPasswordField jpf = new JPasswordField();
            JOptionPane.showConfirmDialog(null, new Object[]{label, jpf}, "Senha do certificado:", JOptionPane.OK_CANCEL_OPTION,JOptionPane.PLAIN_MESSAGE);
            ks.load(null, new String(jpf.getPassword()).toCharArray());
        }
        return ks;
    }
    
    private void populateTreeCertificados() throws KeyStoreException, LoginException, CertificateParsingException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, Exception {
        try {
            ks = ksEntry();
        } catch (KeyStoreException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            throw new Exception("Não foi possível localizar o certificado. \r\nSelecione o driver correspondente ao SmartCard/Token e tente novamente.");
        } catch(NoSuchProviderException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            throw new Exception("Não foi possível localizar o certificado. \r\nSelecione o driver correspondente ao SmartCard/Token e tente novamente.");
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
        getData().put(CERTIFICADOS_DATA, certList);
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
            tabs.setSelectedIndex(TAB_STATUS);
            throw new IOException("Não foi possível determinar o Sistema Operacional");
        }
    }

    private void readArqDrivers(String name) throws IOException, LoginException {
        Drivers drivers = new Drivers();
        Collection<String> drive = null;
        if (name.equals(DRIVERS_WIN)) {
            drive = drivers.winDrivers();
        } else if (name.equals(DRIVERS_LNX)) {
            drive = drivers.linuxDrivers();
        } else if (name.equals(DRIVERS_MAC)) {
            drive = drivers.macDrivers();
        }
        for (String s : drive) {
            File driverRead = new File(s);
            if (driverRead.exists()) {
                try {
                    getProviderCert(driverRead);
                } catch (ProviderException ex) {
                    continue;
                }
                break;
            }
        }
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

    private void selectA1Cert() {
        arquivoA1Chooser = new JFileChooser();
        int returnValue = arquivoA1Chooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            arquivoA1 = arquivoA1Chooser.getSelectedFile();
            txtArquivoCertificado.setText(arquivoA1.getPath());
        }
    }

    private String defautA1Config() {
        StringBuilder sb = new StringBuilder();
        sb.append("caminho=");
        sb.append(System.getProperties().getProperty("line.separator"));
        sb.append("senha=");
        sb.append(System.getProperties().getProperty("line.separator"));
        sb.append("armazenar=false");
        return sb.toString();
    }

    private Properties getA1Properties() throws IOException {
        File file = new File(getHomeUser() + System.getProperties().getProperty("file.separator") + "a1.properties");
        if (!file.exists()) {
            file.createNewFile();
            BufferedWriter out = new BufferedWriter(new FileWriter(file));
            out.write(defautA1Config());
            out.close();
        }
        InputStream is = new FileInputStream(file);
        Properties props = new Properties();
        props.load(is);
        is.close();
        return props;
    }

    private void storeProperties() {
        FileOutputStream oStream = null;
        try {
            Properties props = getA1Properties();
            if (memorizar.isSelected()) {
                if (arquivoA1 != null) {
                    props.setProperty("caminho", arquivoA1.getPath());
                }
                if (jPasswordField1 != null && !new String(jPasswordField1.getPassword()).isEmpty()) {
                    props.setProperty("senha", new String(jPasswordField1.getPassword()));
                }
                props.setProperty("armazenar", String.valueOf(memorizar.isSelected()));
            } else {
                props.setProperty("caminho", "");
                props.setProperty("senha", "");
                props.setProperty("armazenar", "false");
            }
            oStream = new FileOutputStream(getHomeUser() + System.getProperties().getProperty("file.separator") + "a1.properties");
            props.store(oStream, "Atualizado");

        } catch (IOException ex) {
        } finally {
            try {
                if (oStream != null) {
                    oStream.flush();
                    oStream.close();
                }
            } catch (IOException ex) {
            }
        }
    }

    private void assinarA3Action() {
        // Pega o tipo de documento que quer assinar
        String type = getParameter("typeSign");

        // Instancia a classe para escrever no JTextArea
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        writter.append("[" + getDate() + "] Iniciando o processo de assinatura digital");

        // Caso selecione certificados A3 Windows
        int row = jTable1.getSelectedRow();
        Certificados cert = searchCertificate(jTable1.getModel().getValueAt(row, 0).toString());
        try {
            if ("PDF".equalsIgnoreCase(type)) {
                executeJspButton("processReport");
            }
            signA3(cert.getEmitidoPara(), "", writter, type, ks, null);

        } catch (Exception e1) {
            if (e1 instanceof InterruptedException) {
                e1.printStackTrace();
            } else {
                tabs.setSelectedIndex(TAB_STATUS);
                JOptionPane.showMessageDialog(null, "#7# " + e1.getMessage(),
                        "Aconteceu um erro", JOptionPane.ERROR_MESSAGE);
                writter.append("\r\n[ERRO] Falhou o processo de assinatura - Feche o navegador e abra novamente.");
                writter.append("\r\n---------------------------------------\r\n");
                writter.append(e1.getMessage());
            }
        }
        if ("PDF".equalsIgnoreCase(type)) {
            executeJspButton("closePopupApplet");
        } else {
            executeJspButton("closePopup");
        }

    }

    private Certificados searchCertificate(String alias) {
        Certificados cert = null;
        Collection<Certificados> certList = (Collection<Certificados>) getData().get(CERTIFICADOS_DATA);
        for (Certificados c : certList) {
            if (c.getEmitidoPara().contains(alias)) {
                cert = c;
                break;
            }
        }
        return cert;
    }

    private void setJSObject(String fieldName, String value) {
        initializeBrowser();
        JSObject object = (JSObject) mainForm.getMember(fieldName);
        if (object == null) {
            return;
        }
        object.setMember("value", value);
    }

    private void signA1(File cert, String senha, PrintWriter writter, String type) throws Exception {
        writter.append("\r\n[" + getDate() + "] Selecionado certificado A1");
        ProcessSign sign = new ProcessSign();
        if ("XML".equalsIgnoreCase(type)) {
            xml = getJSObject("mainForm:xml");
            setJSObject("mainForm:xmlSignature", sign.assinaRps(xml, cert.getPath(), senha, tagAssinar, "A1", null, null, writter, null, null));
            executeJspButton();
        } else if ("PDF".equalsIgnoreCase(type)) {
            sign.sendPdf(getUrlReport(), getParameters(), cert.getPath(), senha, "A1", null, null,
                    writter, getParameter("msgSucesso"), null, null);
        } else {
            throw new Exception(Assinador.MSG_TIPO_ARQ_NOT_FOUND);
        }
    }

    private void signA3(String alias, String senha, PrintWriter writter, String type, KeyStore ks, X509Certificate x509)
            throws Exception {
        writter.append("\r\n[" + getDate() + "] Selecionado certificado A3");
        ProcessSign sign = new ProcessSign();
        if ("XML".equalsIgnoreCase(type)) {
            xml = getJSObject("mainForm:xml");
            setJSObject("mainForm:xmlSignature", sign.assinaRps(xml, alias, senha, tagAssinar, "A3W", null, null, writter, ks, x509));
            executeJspButton();
        } else if ("PDF".equalsIgnoreCase(type)) {
            sign.sendPdf(getUrlReport(), getParameters(), alias, senha, "A3W", null, null, writter, getParameter("msgSucesso"), ks, x509);
        } else {
            throw new Exception(Assinador.MSG_TIPO_ARQ_NOT_FOUND);
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
        lblTituloJanela = new javax.swing.JLabel();
        lblVersao = new javax.swing.JLabel();
        tabs = new javax.swing.JTabbedPane();
        tabCertificados = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        assinarA3 = new javax.swing.JButton();
        btProcurarDriver = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jButton3 = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        assinarA1 = new javax.swing.JButton();
        txtArquivoCertificado = new javax.swing.JLabel();
        memorizar = new javax.swing.JCheckBox();
        tabStatus = new javax.swing.JPanel();
        btVoltar = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jProgressBar1 = new javax.swing.JProgressBar();
        jSeparator1 = new javax.swing.JSeparator();
        lblIcone = new javax.swing.JLabel();

        setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        setMaximumSize(new java.awt.Dimension(655, 335));
        setMinimumSize(new java.awt.Dimension(655, 335));
        setPreferredSize(new java.awt.Dimension(655, 355));

        jPanel3.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N

        lblTituloJanela.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        lblTituloJanela.setText("Assinador de documentos");

        lblVersao.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        lblVersao.setText("Versão: 2.0.00");

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

        assinarA3.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        assinarA3.setIcon(new javax.swing.ImageIcon(getClass().getResource("/sign.png"))); // NOI18N
        assinarA3.setText("Assinar");
        assinarA3.setToolTipText("Efetuar assinatura");
        assinarA3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assinarA3ActionPerformed(evt);
            }
        });

        btProcurarDriver.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        btProcurarDriver.setIcon(new javax.swing.ImageIcon(getClass().getResource("/search.png"))); // NOI18N
        btProcurarDriver.setText("Procurar driver");
        btProcurarDriver.setToolTipText("Localizar driver Linux/Mac");
        btProcurarDriver.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btProcurarDriverActionPerformed(evt);
            }
        });

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
                        .addComponent(assinarA3, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap())
        );
        tabCertificadosLayout.setVerticalGroup(
            tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(tabCertificadosLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 186, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(tabCertificadosLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(assinarA3)
                    .addComponent(btProcurarDriver)
                    .addComponent(jButton1))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        tabs.addTab("Certificados", new javax.swing.ImageIcon(getClass().getResource("/certificates.png")), tabCertificados); // NOI18N

        jPanel1.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jPanel1.addComponentListener(new java.awt.event.ComponentAdapter() {
            public void componentShown(java.awt.event.ComponentEvent evt) {
                jPanel1ComponentShown(evt);
            }
        });

        jLabel4.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jLabel4.setText("Clique no botão abaixo e localize o arquivo do certificado digital:");

        jButton3.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jButton3.setIcon(new javax.swing.ImageIcon(getClass().getResource("/search.png"))); // NOI18N
        jButton3.setText("Localizar certificado");
        jButton3.setToolTipText("Localizar certificado digital");
        jButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton3ActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        jLabel5.setText("Informe a senha do certificado digital:");

        jPasswordField1.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jPasswordField1.setToolTipText("Informe a senha do certificado digital");

        assinarA1.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        assinarA1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/sign.png"))); // NOI18N
        assinarA1.setText("Assinar");
        assinarA1.setToolTipText("Efetuar assinatura");
        assinarA1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                assinarA1ActionPerformed(evt);
            }
        });

        txtArquivoCertificado.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N

        memorizar.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        memorizar.setText("Memorizar as configurações do certificado.");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(memorizar)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(assinarA1, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 610, Short.MAX_VALUE)
                            .addGroup(jPanel1Layout.createSequentialGroup()
                                .addComponent(jButton3)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addComponent(txtArquivoCertificado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addComponent(jLabel5)
                            .addComponent(jPasswordField1))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(txtArquivoCertificado, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(18, 18, 18)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 78, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(assinarA1)
                    .addComponent(memorizar))
                .addContainerGap())
        );

        txtArquivoCertificado.getAccessibleContext().setAccessibleName("txtArquivoSelecionado");

        tabs.addTab("Certificado A1", new javax.swing.ImageIcon(getClass().getResource("/certificates.png")), jPanel1); // NOI18N

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

        lblIcone.setIcon(new javax.swing.ImageIcon(getClass().getResource("/security-high.png"))); // NOI18N

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addComponent(lblIcone)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(lblTituloJanela)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(lblVersao))
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
                        .addComponent(lblVersao))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(lblIcone))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(lblTituloJanela)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 23, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tabs, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
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
            if(provider != null){
                Security.removeProvider(provider.getName());
            }            
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
            jTextArea1.append(ex.getMessage() + "\r\n");
            ex.printStackTrace(writter);
        }
    }//GEN-LAST:event_jButton1ActionPerformed

    private void btProcurarDriverActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btProcurarDriverActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_btProcurarDriverActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        selectA1Cert();
    }//GEN-LAST:event_jButton3ActionPerformed

    private void assinarA1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assinarA1ActionPerformed
        // Atualiza as informações do preperties
        storeProperties();
        // Faz a assinatura digital
        String type = getParameter("typeSign");
        // Instancia a classe para escrever no JTextArea
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        writter.append("[" + getDate() + "] Iniciando o processo de assinatura digital");
        if ("PDF".equalsIgnoreCase(type)) {
            executeJspButton("processReport");
        }
        try {
            signA1(arquivoA1, new String(jPasswordField1.getPassword()), writter, type);
        } catch (Exception ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            if (ex instanceof InterruptedException) {
                ex.printStackTrace(writter);
            } else {
                JOptionPane.showMessageDialog(null, "#1# " + ex.getMessage(),
                        "Aconteceu um erro", JOptionPane.ERROR_MESSAGE);
                writter.append("\r\n[ERRO] Falhou o processo de assinatura");
                writter.append("\r\n---------------------------------------\r\n");
                writter.append(ex.getMessage());
                writter.append("\r\n Stacktrace: \r\n");
                ex.printStackTrace(writter);
            }
        }
        // Fecha a popup
        if ("PDF".equalsIgnoreCase(type)) {
            executeJspButton("closePopupApplet");
        } else {
            // executeJspButton("closePopup");
        }
    }//GEN-LAST:event_assinarA1ActionPerformed

    private void jPanel1ComponentShown(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_jPanel1ComponentShown
        try {
            // Carrega o properties das configurações do A1.
            Properties props = getA1Properties();
            boolean armazenar = Boolean.valueOf(props.getProperty("armazenar"));
            memorizar.setSelected(armazenar);
            String caminho = props.getProperty("caminho");
            if (caminho != null && !caminho.isEmpty()) {
                txtArquivoCertificado.setText(caminho);
                arquivoA1 = new File(caminho);
            }
            String senha = props.getProperty("senha");
            if (senha != null && !senha.isEmpty()) {
                jPasswordField1.setText(senha);
            }
        } catch (IOException ex) {
            // Não foi possível carregar o arquivo de propriedades
        }

    }//GEN-LAST:event_jPanel1ComponentShown

    private void assinarA3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_assinarA3ActionPerformed
        assinarA3Action();
    }//GEN-LAST:event_assinarA3ActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton assinarA1;
    private javax.swing.JButton assinarA3;
    private javax.swing.JButton btProcurarDriver;
    private javax.swing.JButton btVoltar;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JTable jTable1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JLabel lblIcone;
    private javax.swing.JLabel lblTituloJanela;
    private javax.swing.JLabel lblVersao;
    private javax.swing.JCheckBox memorizar;
    private javax.swing.JPanel tabCertificados;
    private javax.swing.JPanel tabStatus;
    private javax.swing.JTabbedPane tabs;
    private javax.swing.JLabel txtArquivoCertificado;
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
    private JFileChooser arquivoA1Chooser;
    private File arquivoA1;
    private Map<String, Object> data;
    private KeyStore ks;
    private Provider provider;
}
