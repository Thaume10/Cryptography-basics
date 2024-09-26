import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.net.ssl.*;
import java.io.*;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Scanner;

public class SecureServer {
    private static final int SERVER_PORT = 8080;
    private final KeyPair keyPair;
    private static final ArrayList<SSLSocket> clients = new ArrayList<>();
    private static final ArrayList<SSLSocket> securedClients = new ArrayList<>(); // List for secured clients

    public SecureServer() throws Exception {
        // Generate an RSA key pair and certificate
        keyPair = UtilsCrypto.generateKeyPair();
        X509Certificate serverCert = UtilsCrypto.generateCertificate(keyPair, "Secure_Server");

        // Create a secure ServerSocket with is trust manager
        TrustManager[] trustCert = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{serverCert};
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                        // Verify that the client's certificate was signed by the same certificate as the one used by the server
                        String a = String.valueOf(chain[0].getIssuerDN());
                        String b = String.valueOf(serverCert.getSubjectDN());
                        if (chain.length != 1 || !a.equals(b)) {
                            throw new CertificateException("Validity problem from the client certification");
                        }
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                        String a = String.valueOf(chain[0]);
                        String b = String.valueOf(serverCert);
                        if (chain.length != 1 || !a.equals(b)) {
                            throw new CertificateException("Validity problem from the server certification");
                        }
                    }
                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("server-cert", serverCert);
        keyStore.setKeyEntry("server-key", keyPair.getPrivate(), "password".toCharArray(), new java.security.cert.Certificate[]{serverCert});
        keyManagerFactory.init(keyStore, "password".toCharArray());
        sslContext.init(keyManagerFactory.getKeyManagers(), trustCert, null);

        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(SERVER_PORT);
        sslServerSocket.setNeedClientAuth(true);

        // Create and start a thread for handling user input
        new Thread(() -> {
            try {
                handleUserInput();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        // Accept client connections
        while (true) {
            SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
            clients.add(sslSocket);
            System.out.println("New client connected: " + sslSocket.getInetAddress().getHostAddress() + ":" + sslSocket.getPort());

            // Create a new thread to handle the client's messages
            new Thread(new ClientHandler(sslSocket)).start();
        }
    }

    public static void addSecuredClient(SSLSocket client) {
        securedClients.add(client);
        System.out.println("Client added to the secured group: " + client.getInetAddress().getHostAddress() + ":" + client.getPort());
    }

    // Method to remove a client from the secured group
    public static void removeSecuredClient(SSLSocket client) {
        securedClients.remove(client);
        System.out.println("Client removed from the secured group: " + client.getInetAddress().getHostAddress() + ":" + client.getPort());
    }

    // Method to handle user input for adding and removing clients
    public static void handleUserInput() throws IOException {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            String input = scanner.nextLine();
            if (input.startsWith("add")) {
                String[] parts = input.split(" ");
                if (parts.length == 2) {
                    String[] clientInfo = parts[1].split(":");
                    if (clientInfo.length == 2) {
                        for (SSLSocket client : clients) {
                            if (client.getInetAddress().getHostAddress().equals(clientInfo[0]) && client.getPort() == Integer.parseInt(clientInfo[1])) {
                                addSecuredClient(client);
                                break;
                            }
                        }
                    }
                }
            } else if (input.startsWith("remove")) {
                String[] parts = input.split(" ");
                if (parts.length == 2) {
                    String[] clientInfo = parts[1].split(":");
                    if (clientInfo.length == 2) {
                        for (SSLSocket client : securedClients) {
                            if (client.getInetAddress().getHostAddress().equals(clientInfo[0]) && client.getPort() == Integer.parseInt(clientInfo[1])) {
                                removeSecuredClient(client);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    private class ClientHandler implements Runnable {
        private final SSLSocket client;

        public ClientHandler(SSLSocket client) {
            this.client = client;
        }

        @Override
        public void run() {
            try {
                // Read and send messages continuously
                BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                while (true) {
                    try {
                        String encryptedText = in.readLine();
                        if (encryptedText == null) break;
                        String decryptedText = UtilsCrypto.decrypt(keyPair.getPrivate(), encryptedText);
                        String signature = in.readLine();
                        assert decryptedText != null;
                        boolean verified = UtilsCrypto.verify(client.getSession().getPeerCertificates()[0].getPublicKey(), decryptedText, signature);
                        System.out.println("Received message: " + decryptedText);
                        System.out.println("Signature Verified: " + verified);
                        // Send the decrypted message to all connected clients
                        for (SSLSocket connectedClient : clients) {
                            if(connectedClient!=client){
                                if (verified) {
                                    PrintWriter out = new PrintWriter(connectedClient.getOutputStream(), true);
                                    // Check if the client is in the secured group
                                    boolean isSecuredClient = securedClients.contains(connectedClient);
                                    decryptedText = client.getInetAddress().getHostAddress()+":"+client.getPort() +" sent : "+decryptedText;
                                    if (isSecuredClient) {
                                        // Encrypt the message with the client's public key
                                        X509Certificate clientCert = (X509Certificate) connectedClient.getSession().getPeerCertificates()[0];
                                        String encryptedMessageText = UtilsCrypto.encrypt(clientCert, decryptedText);
                                        out.println(encryptedMessageText);
                                        String signature2 = UtilsCrypto.sign(keyPair.getPrivate(), decryptedText);
                                        out.println(signature2);
                                    } else {
                                        out.println(encryptedText);
                                        String signature2 = UtilsCrypto.sign(keyPair.getPrivate(), encryptedText);
                                        out.println(signature2);
                                    }
                                    String signature2 = UtilsCrypto.sign(keyPair.getPrivate(), decryptedText);
                                    out.println(signature2);
                                } else {
                                    System.out.println("Signature not verified");
                                }
                            }

                        }
                    } catch (SocketException e) {
                        System.out.println("Client disconnected: " + client.getInetAddress().getHostAddress() + ":" + client.getPort());
                        break;
                    } catch (Exception e) {
                        e.printStackTrace();
                        break;
                    }
                }
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                clients.remove(client);
                securedClients.remove(client);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    client.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        new SecureServer();
    }
}
