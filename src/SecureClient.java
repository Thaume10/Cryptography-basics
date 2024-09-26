import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SecureClient {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 8080;

    private final KeyPair keyPair;
    private final X509Certificate cert;
    private final SSLSocket sslSocket;
    private final BufferedReader in;
    private final PrintWriter out;

    public SecureClient() throws Exception {
        // Generate an RSA key pair
        keyPair = UtilsCrypto.generateKeyPair();
        X509Certificate clientCert = UtilsCrypto.generateCertificate(keyPair, "Secure_Server");
        cert = clientCert;
        // Create a secure Socket
        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("client-cert", clientCert);
        keyStore.setKeyEntry("client-key", keyPair.getPrivate(), "password".toCharArray(), new java.security.cert.Certificate[]{clientCert});
        keyManagerFactory.init(keyStore, "password".toCharArray());
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{cert};
                    }
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // Verify that the client's certificate was signed by the same certificate as the one used by the server
                        String a = String.valueOf(chain[0]);
                        String b = String.valueOf(cert);
                        if (chain.length != 1 || !a.equals(b)) {
                            throw new CertificateException("Validity problem from the client certification");
                        }
                    }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        String a = String.valueOf(chain[0].getIssuerDN());
                        String b = String.valueOf(cert.getSubjectDN());
                        if (chain.length != 1 || !a.equals(b)) {
                            throw new CertificateException("Validity problem from the server certification");
                        }
                    }
                }
        };
        sslContext.init(keyManagerFactory.getKeyManagers(), trustAllCerts, null);
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        sslSocket = (SSLSocket) sslSocketFactory.createSocket(SERVER_HOST, SERVER_PORT);
        in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
        out = new PrintWriter(sslSocket.getOutputStream(), true);
        // Start separate threads for reading and writing messages
        new Thread(new IncomingMessageHandler()).start();
        new Thread(new OutgoingMessageHandler()).start();
    }

    private class IncomingMessageHandler implements Runnable {
        @Override
        public void run() {
            try {
                String receivedMessage;

                while ((receivedMessage = in.readLine()) != null) {
                    // Decrypt the response with the client's private key
                    String decryptedMessage = UtilsCrypto.decrypt(keyPair.getPrivate(), receivedMessage);
                    String signature = in.readLine();
                    assert decryptedMessage != null;
                    if (UtilsCrypto.verify(sslSocket.getSession().getPeerCertificates()[0].getPublicKey(), decryptedMessage, signature)) {
                        System.out.println(decryptedMessage);
                        System.out.println("Signature Verified");
                    } else {
                        System.out.println("Signature not verified");
                    }
                    in.readLine();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    private class OutgoingMessageHandler implements Runnable {
        @Override
        public void run() {
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            String message;
            try {
                while ((message = userInput.readLine()) != null) {
                    // Encrypt the message with the server's public key
                    X509Certificate serverCert = (X509Certificate) sslSocket.getSession().getPeerCertificates()[0];
                    out.println(UtilsCrypto.encrypt(serverCert, message));
                    String signature = UtilsCrypto.sign(keyPair.getPrivate(), message);
                    out.println(signature);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        new SecureClient();
    }
}
