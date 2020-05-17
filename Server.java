/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author arpitasikder
 */
import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server {

    static String hashAlgorithm = "MD5";
    static String hashAlgorithm1 = "SHA-1";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, Exception {

        Random rand = new Random();

        int port = 6666;
        ServerSocket Server_socket;
        Socket sock;
        BufferedReader in;
        PrintWriter out;
        int Ns = rand.nextInt(599) + 1; //Server nonce
        int Nc; //Client nonce
        String[] ClientHelloMessage;

        String client_packet1, client_packet2, server_packet1;

        BufferedReader userInput;

        String write_algo, mac_algo, KeyExchange_algo;
        int key1, key2, key3, key4;

        try {
            System.out.print("Server Connected..");
            Server_socket = new ServerSocket(port);
            System.out.println("Listening on port " + Server_socket.getLocalPort());
            sock = Server_socket.accept();
            Server_socket.close();
            in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream()));
            out = new PrintWriter(sock.getOutputStream());

        } catch (Exception e) {
            System.out.println("An error occurred while opening sock.");
            System.out.println(e.toString());
            return;
        }
        /**
         * *****************************************************************************************
         * receive hello packet from client
         * ******************************************************************************************
         */
        System.out.println("Client Hello Message:----------------------------------------------------------------------------------------------------------------------------------");
        System.out.print("\n");
        System.out.print("Waiting for Client Hello Message........\n");
        client_packet1 = in.readLine();
        System.out.println("Client's list of ciphers : " + client_packet1);
        ClientHelloMessage = client_packet1.split(" ");
        Nc = Integer.parseInt(ClientHelloMessage[0]);
        mac_algo = ClientHelloMessage[1];
        write_algo = ClientHelloMessage[3];  //change the index value to 4 for 3DES that is thriple DES cipher
        KeyExchange_algo = ClientHelloMessage[5];
        System.out.print("Client Hello Message received sucessfully\n");
        System.out.print("\n");
        /**
         * ******************************************************************************************************************************
         * Server send Hello Message to the Client with the chosen ciphers
         * *******************************************************************************************************************************
         */
        System.out.println("Server Hello Message:-------------------------------------------------------------------------------------------------------------------------------");
        String hello_message = mac_algo + " " + write_algo + " " + KeyExchange_algo;
        //System.out.print("Chosen Ciphers By the Server"+hello_message+"\n");
        System.out.print("Selected ciphers are:-\n");
        System.out.print("write_algo: " + write_algo + "\n");
        System.out.print("mac_algo: " + mac_algo + "\n");
        System.out.print("KeyExchange_algo: " + KeyExchange_algo + "\n");
        out.println(hello_message);
        out.flush();
        System.out.print("Server Hello Message sent sucessfully\n");
        System.out.print("\n");

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 1 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        /**
         * ******************************************************************************************************************************
         * Server creates its own public and private key
         * *******************************************************************************************************************************
         */
        KeyPairGenerator key = KeyPairGenerator.getInstance("RSA");
        key.initialize(1024);
        KeyPair Server_keyPair = key.generateKeyPair();
        PublicKey Server_PU = Server_keyPair.getPublic();
        PrivateKey Server_PR = Server_keyPair.getPrivate();

        /**
         * ******************************************************************************************************************************
         * The certificate along with the digital signature obtained from the
         * Certificate Authority
         * ******************************************************************************************************************************
         */
        System.out.println("The certificate along with the digital signature obtained from the Certificate Authority:-------------------------------------------------------------");
        String ServerPUString = Base64.getEncoder().encodeToString(Server_PU.getEncoded());
        System.out.print("Server String Public key: " + ServerPUString + "\n");
        String identity = "Arpita_Sikder";
        String identity1 = Ns + write_algo + mac_algo + ServerPUString + identity;
        System.out.print("Certificate Contents: " + identity1 + "\n");
        CA ca = new CA();
        String hashcode = ca.CertificateEncrypt(identity1);
        String CAname = "COE817Authority";

        /**
         * *******************************************************************************************************************************
         * certificate send by the server
         * *******************************************************************************************************************************
         */
        System.out.println("Certificate send by the server:---------------------------------------------------------------------------------------------------------------------");
        server_packet1 = Ns + " " + write_algo + " " + mac_algo + " " + ServerPUString + " " + identity + " " + identity1 + " " + hashcode + " " + CAname;
        out.println(server_packet1);
        out.flush();
        System.out.println("Certificate: " + server_packet1);

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 2 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");
        /**
         * ********************************************************************************************************************************
         * Server receives the encrypted pre-master-secret send by client to
         * decrypt it with its private key
         * ********************************************************************************************************************************
         */
        System.out.println("Server receives the encrypted pre-master-secret send by client to decrypt it with its private key:----------------------------------------------------");
        client_packet2 = in.readLine();
        System.out.print("Encrypted pre_master_secret: " + client_packet2 + "\n");
        byte[] decode = Base64.getDecoder().decode(client_packet2);
        Cipher decrypt = Cipher.getInstance("RSA");
        decrypt.init(Cipher.DECRYPT_MODE, Server_PR);
        byte[] decoded = decrypt.doFinal(decode);
        String x = new String(decoded);
        System.out.print("Decrypted pre_master_secret" + x + "\n");

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 3 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");
        /**
         * *********************************************************************************************************************************
         * creating 4 sub keys after computing the master key from the decrypted
         * pre-master-secret key
         * x********************************************************************************************************************************
         */
        System.out.println("Caculating master_secret and then creating 4 sub keys:------------------------------------------------------------------------------------------------");
        int master_secret = (Integer.parseInt(x) * Nc * Ns);
        if (master_secret < 0) {
            master_secret = master_secret * (-1);
        }
        System.out.println("Master Secret: " + master_secret);
        key2 = master_secret % 8642;
        System.out.println("key2: " + key2);
        key4 = master_secret % 8642;
        System.out.println("key4: " + key4);
        key1 = master_secret % 3456;
        System.out.println("key1: " + key1);
        key3 = master_secret % 3456;
        System.out.println("key3: " + key3);

        String xy = "" + key2;
        int k;
        if (xy.length() != 4) {
            for (k = xy.length(); k <= 4; k++) {
                xy = xy + "8";
            }

        }
        //convert 1   

        String desKey = xy + xy + xy + xy;
        byte[] keyBytes = DatatypeConverter.parseHexBinary(desKey);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        SecretKey keyMc = factory.generateSecret(new DESKeySpec(keyBytes)); //encryption

        // covert 2   
        String desKey1 = xy + xy + xy + xy;
        byte[] keyBytes1 = DatatypeConverter.parseHexBinary(desKey1);

        SecretKeyFactory factory1 = SecretKeyFactory.getInstance("DES");
        SecretKey keyMs = factory1.generateSecret(new DESKeySpec(keyBytes1)); //decryption

        //for 3DES
        String desKey0 = xy + xy + xy + xy;
        for (int a = 0; a < 2; a++) {
            desKey0 = desKey0 + desKey0;
        }
        byte[] keyBytes0 = DatatypeConverter.parseHexBinary(desKey0);

        SecretKeyFactory factory0 = SecretKeyFactory.getInstance("DESede");
        SecretKey keyMc1 = factory0.generateSecret(new DESedeKeySpec(keyBytes0)); //

        SecretKeyFactory factory11 = SecretKeyFactory.getInstance("DESede");
        SecretKey keyMs1 = factory11.generateSecret(new DESedeKeySpec(keyBytes0)); //

        //convert 3
        String desKey2 = xy + xy + xy + xy;
        byte[] keyBytes2 = DatatypeConverter.parseHexBinary(desKey2);

        SecretKeyFactory factory2 = SecretKeyFactory.getInstance("DES");
        SecretKey keyKc = factory2.generateSecret(new DESKeySpec(keyBytes2)); //validation send

        //convert 4
        String desKey3 = xy + xy + xy + xy;
        byte[] keyBytes3 = DatatypeConverter.parseHexBinary(desKey3);

        SecretKeyFactory factory3 = SecretKeyFactory.getInstance("DES");
        SecretKey keyKs = factory3.generateSecret(new DESKeySpec(keyBytes1));   //validation received

        String client_change_cipher_spec = in.readLine();
        System.out.print("Server change_cipher_spec: " + client_change_cipher_spec + "\n");

        String receivedMAC = in.readLine();

        String mac_send = "" + client_packet1 + server_packet1 + client_packet2 + BigInteger.valueOf(key4);
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        md.update(mac_send.getBytes());
        byte[] hashValue = md.digest();
        String StringHashValue = new String(Base64.getEncoder().encode(hashValue));

        MessageDigest md1 = MessageDigest.getInstance(hashAlgorithm1);
        md1.update(mac_send.getBytes());
        byte[] hashValue1 = md.digest();
        String StringHashValue1 = new String(Base64.getEncoder().encode(hashValue1));

        String mac = StringHashValue + StringHashValue1;
        out.println(mac);
        out.flush();

        System.out.println("Server Mac: " + mac);

        System.out.println("receivedMAC: " + receivedMAC);
        if (!mac.equals(receivedMAC)) {
            throw new Exception("MACs do not equal!");
        }

        String change_cipher_spec = "1";
        out.println(change_cipher_spec);
        out.flush();
        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 4 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        System.out.println("**************************************************************************************************************************************************");
        System.out.println("SSL HANDSHAKE ESTABLISHED SUCCESSFULLY");
        System.out.println("***************************************************************************************************************************************************");

        try {

            userInput = new BufferedReader(new InputStreamReader(System.in));

            Cipher encrypt1 = Cipher.getInstance("DES");
            Cipher decrypt1 = Cipher.getInstance("DES");
            encrypt1.init(Cipher.ENCRYPT_MODE, keyMc); //encrypt des
            decrypt1.init(Cipher.DECRYPT_MODE, keyMs);  //dycrypt des

            Cipher encrypt2 = Cipher.getInstance("DESede");
            Cipher decrypt2 = Cipher.getInstance("DESede");
            encrypt2.init(Cipher.ENCRYPT_MODE, keyMc1);
            decrypt2.init(Cipher.DECRYPT_MODE, keyMs1);

            String s_ciphertext_receive = "";
            String s_plaintext_receive = "";
            String receiveMessage, sendMessage;
            while (true) {
                System.out.print("\n");
                System.out.print("Type in to send message.\n");
                System.out.print("Type 'EXIT' to end the program.\n");
                System.out.print("Enter:");

                sendMessage = userInput.readLine();  // keyboard reading

                if (sendMessage.equals("EXIT")) {
                    out.println("EXIT");
                    out.flush();
                    System.out.println("**************************************************************************************************************************************************");
                    System.out.println("SSL Record Layer Implementated Successfully ");
                    System.out.println("***************************************************************************************************************************************************");
                    break;
                }

                if (!sendMessage.equals("EXIT")) {

                    //MESSAGE ENCRYPTION
                    switch (write_algo) {
                        case "DES":
                            byte[] b_plaintext = sendMessage.getBytes("UTF8");
                            byte[] b_ciphertext = encrypt1.doFinal(b_plaintext);
                            String ciphertext = Base64.getEncoder().encodeToString(b_ciphertext);

                            out.println(ciphertext);       // sending to server
                            out.flush();                    // flush the data

                            System.out.print("\n");
                            System.out.println("CIPHERTEXT SEND: " + ciphertext);
                            break;
                        case "3DES":
                            byte[] b_plaintext_send1 = sendMessage.getBytes("UTF8");
                            byte[] b_ciphertext_send1 = encrypt2.doFinal(b_plaintext_send1);
                            String ciphertext_send1 = Base64.getEncoder().encodeToString(b_ciphertext_send1);

                            //Send message
                            out.println(ciphertext_send1);
                            out.flush();

                            //Debugging
                            System.out.print("\n");
                            System.out.println("CIPHERTEXT SEND: " + ciphertext_send1 + "\n");
                            break;
                    }

                    //MESSAGE MAC VALIDATION
                    switch (mac_algo) {
                        case "SHA-1":
                            MAC m = new MAC();
                            String encrypedMacMessage = m.mac(sendMessage, mac_algo, keyKc);
                            System.out.print("\n");
                            System.out.print(encrypedMacMessage + "\n");
                            out.println(encrypedMacMessage);
                            out.flush();
                            System.out.print("sucessfully send \n");
                            break;
                        case "MD5":
                            MAC m1 = new MAC();
                            String encrypedMacMessage2 = m1.mac(sendMessage, mac_algo, keyKc);
                            System.out.print(encrypedMacMessage2 + "\n");
                            out.println(encrypedMacMessage2);
                            out.flush();
                            System.out.print("sucessfully send \n");
                            break;

                    }
                }

                if ((receiveMessage = in.readLine()) != "EXIT") //receive from server
                {

                    s_ciphertext_receive = receiveMessage;
                    if (s_ciphertext_receive.equals("EXIT")) {
                        break;
                    }

                    switch (write_algo) {
                        case "DES":
                            byte[] b_ciphertext_receive = Base64.getDecoder().decode(receiveMessage);
                            byte[] b_plaintext_receive = decrypt1.doFinal(b_ciphertext_receive);
                            s_plaintext_receive = new String(b_plaintext_receive, "UTF8");

                            //Debugging
                            System.out.print("\n");
                            System.out.println("CIPERTEXT RECEIVED:" + s_ciphertext_receive);
                            //System.out.print("\n");
                            System.out.println("DECRYPTED MESSAGE>>>>>>>>>>>>>>>:" + s_plaintext_receive);
                            break;
                        case "3DES":
                            byte[] b_ciphertext1 = Base64.getDecoder().decode(receiveMessage);

                            byte[] b_plaintext1 = decrypt2.doFinal(b_ciphertext1);
                            String s_plaintext1 = new String(b_plaintext1);

                            System.out.print("\n");
                            System.out.println("DECRYPTED MESSAGE>>>>>>>>>>>>>>>:" + s_plaintext1);
                            break;

                    }

                    receiveMessage = in.readLine();

                    String messagehashencrypted = receiveMessage;
                    System.out.print("\n");
                    System.out.print("MESSAGE AUTHENTICATION CODE RECEIVED:  " + messagehashencrypted);

                    switch (mac_algo) {
                        case "SHA-1":
                            MAC m = new MAC();
                            boolean result = m.ValidateMac(s_plaintext_receive, messagehashencrypted, mac_algo, keyKc);
                            if (result == true) {
                                System.out.print("MESSAGE AUTHENTICATION SUCCESSFUL\n");
                            } else {
                                System.out.print("Validation failed\n");
                            }
                            break;
                        case "MD5":
                            MAC m1 = new MAC();
                            boolean result1 = m1.ValidateMac(messagehashencrypted, s_plaintext_receive, mac_algo, keyKc);
                            if (result1 == true) {
                                System.out.print("Validation passed");
                            } else {
                                System.out.print("Validation failed");
                            }
                            break;
                    }

                }

            }
        } catch (Exception e) {
            System.out.println("Sorry, Connection lost. An error has occurred.");
            System.out.println("Error:  " + e);
            System.exit(1);
        }

    }

}
