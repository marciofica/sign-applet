
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
                    assinarA3.setEnabled(false);
                    try {
                        initialize();
                    } catch (LoginException ex) {
                        tabs.setSelectedIndex(TAB_STATUS);
                        ex.printStackTrace(writter);
                    } catch (KeyStoreException ex) {
                        tabs.setSelectedIndex(TAB_STATUS);
                        ex.printStackTrace(writter);
                    } catch (Exception ex) {
                       // tabs.setSelectedIndex(TAB_STATUS);
                       jTextArea1.append(ex.getMessage());
                    }
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void getTituloJanela() {
        String titulo = getParameter("tituloJanela");
        if (titulo != null && !titulo.isEmpty()) {
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
            ks = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
            ks.load(null, null);
        } else {
            if (provider == null) {
                findDriverCerticate();
            }
            ks = KeyStore.getInstance("PKCS11", provider);
            JLabel label = new JLabel("Digite a senha do certificado:");
            jpf = new JPasswordField();
            JOptionPane.showConfirmDialog(null, new Object[]{label, jpf}, "Senha do certificado:", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            ks.load(null, new String(jpf.getPassword()).toCharArray());
        }
        return ks;
    }

    private void populateTreeCertificados() throws KeyStoreException, LoginException, CertificateParsingException, NoSuchProviderException, IOException, NoSuchAlgorithmException, CertificateException, Exception {
        try {
            ks = ksEntry();
        } catch (KeyStoreException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace();
            throw new Exception("Não foi possível localizar o certificado. \r\nSelecione o driver correspondente ao SmartCard/Token e tente novamente.");
        } catch (NoSuchProviderException ex) {
            tabs.setSelectedIndex(TAB_STATUS);
            ex.printStackTrace();
            throw new Exception("Não foi possível localizar o certificado. \r\nSelecione o driver correspondente ao SmartCard/Token e tente novamente.");
        }
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        IcpBrasilUtils icpBrasil = new IcpBrasilUtils();
        X509Certificate certificatez;
        Collection<Certificados> certList = null;
        for (Enumeration<String> enumKs = ks.aliases(); enumKs.hasMoreElements();) {
            String alias = enumKs.nextElement().toString();
            certificatez = (X509Certificate) ks.getCertificate(alias);
            if (!icpBrasil.isFinalCertificate(certificatez)) {
                String name = icpBrasil.getNome(certificatez.getSubjectX500Principal());
                String entidadeCertificadora = icpBrasil.getEntidadeCertificadora(certificatez
                        .getSubjectX500Principal());
                if (entidadeCertificadora.contains("ICP-Brasil")) {
                    if (certList == null) {
                        certList = new ArrayList<Certificados>();
                    }
                    Certificados cert = new Certificados();
                    cert.setCertificado(certificatez);
                    cert.setChecked(false);
                    cert.setEmitidoPara(name);
                    cert.setEmitidoPor(icpBrasil.getNome(certificatez.getIssuerX500Principal()));
                    cert.setEntidade(icpBrasil.getEntidadeCertificadora(certificatez
                            .getIssuerX500Principal()));
                    cert.setValidoAte(sdf.format(certificatez.getNotAfter()));
                    cert.setAlias(ks.getCertificateAlias(certificatez));
                    certList.add(cert);
                }
            }
        }
        setCertModel(certList);
        getData().put(CERTIFICADOS_DATA, certList);
        
        if(jTable1.getModel().getRowCount() > 0){
            jTable1.setRowSelectionInterval(0, 0);
            assinarA3.setEnabled(true);
        } else {
            assinarA3.setEnabled(false);
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
        SimpleDateFormat spf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
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
        Object[] params = new Object[5];
        params[0] = getJSObject("mainForm:p1");
        params[1] = getJSObject("mainForm:p2");
        params[2] = getJSObject("mainForm:p3");
        params[3] = getJSObject("mainForm:p4");
        params[4] = getParameter("urlServlet");
        return params;
    }

    private String getUrlReport() {
        return getJSObject("mainForm:returnUrl");
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
                    selectedFile = driverRead;
                } catch (ProviderException ex) {
                    continue;
                }
                break;
            }
        }
    }

    private void initialize() throws LoginException, KeyStoreException, Exception {
        assinarA3.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        assinarA3Action();
                    }
                }).start();
            }
        });
        assinarA1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
               new Thread(new Runnable() {
                    @Override
                    public void run() {
                        assinarA1Action();
                    }
                }).start();
            }
        });
        
        populateTreeCertificados();
        
            
        xml = getParameter("xml");
        tagAssinar = getParameter("tagAssinar");
    }

    private void selectA1Cert() {
        arquivoA1Chooser = new JFileChooser();
        int returnValue = arquivoA1Chooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            arquivoA1 = arquivoA1Chooser.getSelectedFile();
            areaCertificado.setText(arquivoA1.getPath());
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

    private void configProgressBar() {
        jProgressBar1.setIndeterminate(false);
        jProgressBar1.setMinimum(0);
        jProgressBar1.setMaximum(100);
        jProgressBar1.setValue(100);
        jProgressBar1.setStringPainted(true);
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

    private void signA3(String alias, String senha, PrintWriter writter, String type, X509Certificate x509)
            throws Exception {
        writter.append("\r\n[" + getDate() + "] Selecionado certificado A3");
        ProcessSign sign = new ProcessSign();
        if ("XML".equalsIgnoreCase(type)) {
            xml = getJSObject("mainForm:xml");
            setJSObject("mainForm:xmlSignature", sign.assinaRps(xml, alias, senha, tagAssinar, getOsAlias(), selectedFile, null, writter, ks, x509));
            executeJspButton();
        } else if ("PDF".equalsIgnoreCase(type)) {
            sign.sendPdf(getUrlReport(), getParameters(), alias, senha, getOsAlias(), selectedFile, null, writter, getParameter("msgSucesso"), ks, x509);
        } else {
            throw new Exception(Assinador.MSG_TIPO_ARQ_NOT_FOUND);
        }
    }

    private String getOsAlias() {
        if (getOs().contains("Windows")) {
            return "A3W";
        } else {
            return "A3L";
        }
    }
    
    private void assinarA3Action() {
        tabs.setSelectedIndex(TAB_STATUS);
        jProgressBar1.setIndeterminate(true);
        // Pega o tipo de documento que quer assinar
        String type = getParameter("typeSign");
        
        // LImpa conteúdo da textArea
        jTextArea1.setText("");        
        
        // Instancia a classe para escrever no JTextArea
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        writter.append("[" + getDate() + "] Iniciando o processo de assinatura digital");

        // Caso selecione certificados A3 Windows
        int row = jTable1.getSelectedRow();
        
        if(jTable1.getModel().getRowCount() == 1){
            jTable1.setRowSelectionInterval(0, 0);
            row = jTable1.getSelectedRow();
        } else {
            if(row == -1){
                writter.append("\r\n[" + getDate() + "] Você deve selecionar um certificado para fazer a assinatura.");
                configProgressBar();
                return;
            }
        }
        
        Certificados cert = searchCertificate(jTable1.getModel().getValueAt(row, 0).toString());
        try {
            if ("PDF".equalsIgnoreCase(type)) {
                tabs.setSelectedIndex(TAB_STATUS);
                executeJspButton("processReport");
            }
            String senha = "";
            if (jpf != null) {
                senha = new String(jpf.getPassword());
            }
            signA3(cert.getAlias(), senha, writter, type, null);            
        } catch (Exception e1) {
            configProgressBar();
            String msg = "";
            if (e1 instanceof InterruptedException) {
                msg = "O certificado foi removido, impossibilitando a comunicação.";
            } else {
                if(e1.getCause() != null){
                    msg = e1.getCause().getMessage();
                } else {
                    msg = e1.getMessage();
                }
            }
            JOptionPane.showMessageDialog(null, "#7# " + msg, "Aconteceu um erro", JOptionPane.ERROR_MESSAGE);
            writter.append("\r\n[ERRO] Falhou o processo de assinatura - Feche o navegador e abra novamente.");
            writter.append("\r\n---------------------------------------\r\n");
            writter.append(msg);
        }
        configProgressBar();
        executeJspButton("closePopupApplet");
    }
    
    private void assinarA1Action(){
        tabs.setSelectedIndex(TAB_STATUS);
        jProgressBar1.setIndeterminate(true);
        // Atualiza as informações do preperties
        storeProperties();
        // Faz a assinatura digital
        String type = getParameter("typeSign");
        
        // Limpa conteúdo da textArea
        jTextArea1.setText("");
        
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
            configProgressBar();
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
                configProgressBar();
                return;
            }
        }
        configProgressBar();
        // Fecha a popup
        if("PDF".equalsIgnoreCase(type)){
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
        lblTituloJanela = new javax.swing.JLabel();
        lblVersao = new javax.swing.JLabel();
        tabs = new javax.swing.JTabbedPane();
        tabCertificados = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTable1 = new javax.swing.JTable();
        assinarA3 = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jButton3 = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        assinarA1 = new javax.swing.JButton();
        memorizar = new javax.swing.JCheckBox();
        jScrollPane3 = new javax.swing.JScrollPane();
        areaCertificado = new javax.swing.JTextArea();
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
        lblVersao.setText("Versão: 2.0.01");

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
                    .addComponent(jButton1))
                .addContainerGap(19, Short.MAX_VALUE))
        );

        tabs.addTab("Certificados", new javax.swing.ImageIcon(getClass().getResource("/certificates.png")), tabCertificados); // NOI18N

        jPanel1.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        jPanel1.setMaximumSize(new java.awt.Dimension(630, 251));
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

        memorizar.setFont(new java.awt.Font("SansSerif", 0, 11)); // NOI18N
        memorizar.setText("Memorizar as configurações do certificado.");

        areaCertificado.setEditable(false);
        areaCertificado.setColumns(20);
        areaCertificado.setFont(new java.awt.Font("SansSerif", 0, 12)); // NOI18N
        areaCertificado.setLineWrap(true);
        areaCertificado.setRows(5);
        jScrollPane3.setViewportView(areaCertificado);

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
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(jLabel4, javax.swing.GroupLayout.DEFAULT_SIZE, 610, Short.MAX_VALUE)
                                .addGroup(jPanel1Layout.createSequentialGroup()
                                    .addComponent(jButton3)
                                    .addGap(455, 455, 455))
                                .addComponent(jScrollPane3))
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(jLabel5)
                                .addComponent(jPasswordField1)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(22, 22, 22)
                .addComponent(jLabel4)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButton3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 54, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel5)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(38, 38, 38)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(assinarA1)
                    .addComponent(memorizar))
                .addContainerGap())
        );

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
                .addComponent(jScrollPane2, javax.swing.GroupLayout.DEFAULT_SIZE, 168, Short.MAX_VALUE)
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
        // LImpa conteúdo da textArea
        jTextArea1.setText("");
        tabs.setSelectedIndex(TAB_CERTIFICADO);
    }//GEN-LAST:event_btVoltarActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        PrintWriter writter = new PrintWriter(new TextComponentWriter(jTextArea1));
        try {
            if (provider != null) {
                Security.removeProvider(provider.getName());
            }
            populateTreeCertificados();
            if(jTable1.getModel().getRowCount() > 0){
                jTable1.setRowSelectionInterval(0, 0);
                assinarA3.setEnabled(true);
            } else {
                assinarA3.setEnabled(false);
            }
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

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        selectA1Cert();
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jPanel1ComponentShown(java.awt.event.ComponentEvent evt) {//GEN-FIRST:event_jPanel1ComponentShown
        try {
            // Carrega o properties das configurações do A1.
            Properties props = getA1Properties();
            boolean armazenar = Boolean.valueOf(props.getProperty("armazenar"));
            memorizar.setSelected(armazenar);
            String caminho = props.getProperty("caminho");
            if (caminho != null && !caminho.isEmpty()) {
                areaCertificado.setText(caminho);
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

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea areaCertificado;
    private javax.swing.JButton assinarA1;
    private javax.swing.JButton assinarA3;
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
    private javax.swing.JScrollPane jScrollPane3;
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
    private JPasswordField jpf;
    private File selectedFile;
}
