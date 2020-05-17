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
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.DESedeKeySpec;

class Client {

    static String hashAlgorithm = "MD5";
    static String hashAlgorithm1 = "SHA-1";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, Exception {

        String write_algo, mac_algo, KeyExchange_algo;
        int Key1, Key2, Key3, Key4;
        Random rand = new Random();
        String host = "localhost";

        int port = 6666;

        Socket sock;

        BufferedReader in;
        PrintWriter out;

        BufferedReader userInput;

        try {
            System.out.print("Client Connecting...");
            System.out.println("Connecting to " + host + " on port " + port);
            sock = new Socket(host, port);
            in = new BufferedReader(
                    new InputStreamReader(sock.getInputStream()));
            out = new PrintWriter(sock.getOutputStream());

        } catch (Exception e) {
            System.out.println("An error occurred while opening sock.");
            System.out.println(e.toString());
            return;
        }

        String client_packet1, client_packet2, server_packet1, server_packet2;

        //client nonce to prevent replay attacks
        int Nc = rand.nextInt(599) + 1;
        int Ns = 0;
        String pre_master_secret = "5896";
        String[] ServerHelloMessage;
        String trusted_CAname = "COE817Authority";
        String ExpectedServerName = "Arpita_Sikder";

        /**
         * **************************************************************************************
         * Starting Phase 1 Implementation
         * **************************************************************************************
         */
        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Starting....");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        //System.out.print("Phase 1 starting\n");
        /**
         * **************************************************************************************
         * Hello Packet Send By Client
         * **************************************************************************************
         */
        System.out.print("\n");
        System.out.println("Client Hello:-----------------------------------------------------------------------------------------------------------------------------------------");
        String ListOfAlgorithms = "SHA-1 MD5 DES 3DES RSA DH";
        client_packet1 = Integer.toString(Nc) + " " + ListOfAlgorithms;
        out.println(client_packet1);
        out.flush();
        System.out.println("Client's list of ciphers : " + client_packet1);
        System.out.print("Client Hello Message sucessfully send!\n");

        /**
         * **************************************************************************************
         * Hello Packet Received from Server
         * ***************************************************************************************
         */
        System.out.print("\n");
        System.out.println("Server Hello:-----------------------------------------------------------------------------------------------------------------------------------------");
        String Server_hello_message = in.readLine();
        ServerHelloMessage = Server_hello_message.split(" ");
        mac_algo = ServerHelloMessage[0];
        write_algo = ServerHelloMessage[1];
        KeyExchange_algo = ServerHelloMessage[2];
        System.out.print("Selected ciphers are:-\n");
        System.out.print("write_algo: " + write_algo + "\n");
        System.out.print("mac_algo: " + mac_algo + "\n");
        System.out.print("KeyExchange_algo: " + KeyExchange_algo + "\n");
        System.out.print("Server Hello Message received sucessfully\n");

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 1 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        /**
         * **************************************************************************************
         * starting Phase 2 implementation
         * ****************************************************************************************
         * /****************************************************************************************
         * Certificate Received from Server
         * ***************************************************************************************
         */
        System.out.print("\n");
        System.out.println("Server Certificate:----------------------------------------------------------------------------------------------------------------------------------");
        server_packet1 = in.readLine();
        System.out.print("server_packet1: " + server_packet1 + "\n");
        System.out.print("Server Certificate received sucessfully\n");
        System.out.print("\n");

        ServerHelloMessage = server_packet1.split(" ");

        //Server nonce value obtained from Hello message
        Ns = Integer.parseInt(ServerHelloMessage[0]);
        mac_algo = ServerHelloMessage[2];  //validation
        write_algo = ServerHelloMessage[1];

        //this is to retrieve the Sever key from the Server certificate  
        System.out.print("\n");
        System.out.println("Extracting values from the Server certificate:----------------------------------------------------------------------------------------------------- ");

        String ServerPUn = ServerHelloMessage[3];
        System.out.print("ServerPublicKey: " + ServerPUn + "\n");

        String identity = ServerHelloMessage[4];
        System.out.print("ServerName:  " + identity + "\n");
        String identity1 = ServerHelloMessage[5];
        System.out.print("CertificateContent:  " + identity1 + "\n");
        String hashcode = ServerHelloMessage[6];
        System.out.print("Hash digest of the certificate contents:  " + hashcode + "\n");
        String CertificateCAname = ServerHelloMessage[7];
        System.out.print("CertificateAName:  " + CertificateCAname + "\n");

        /**
         * *********************************************************************************************************************
         * getting the Server public key from CA/certificate
         * **********************************************************************************************************************
         */
        System.out.print("\n");
        System.out.println("Getting the Server public key from CA/certificate:----------------------------------------------------------------------------------------------------");

        byte[] decryptedkey = Base64.getDecoder().decode(ServerPUn);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decryptedkey);
        PublicKey PU_a = KeyFactory.getInstance("RSA").generatePublic(keySpec);
        System.out.println("Success!");
        System.out.println("A's public key: " + PU_a);
        System.out.print("Server Public Key extracted from the certificate sucessfully\n");

        /**
         * ********************************************************************************************************************
         * > creating a CA object for authentication purpose in the later steps!
         * *********************************************************************************************************************
         */
        CA certificateAuthority = new CA();

        /**
         * ********************************************************************************************************************
         * Server public key known by everyone
         * ********************************************************************************************************************
         */
        String CA_PublicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsHLahK/EoSRcn4Ek8SRxOddd4c1aCKO9L+rmRdgLzxLGDuFXE5lH8LR4OIdBxXuI2r6BlToEKSz59uzAZHoI3rUXCpWSYB1mfq4A37hCW9EAm3D/9Ln0faYIxsbZ8+20njBKDZo6jb2FLtX8bBUX33oJ+u95r6hev2oyfmMb5027VlOA9vZbugBP3XUa0cgsWM1quNTXcQxj0ncLg9yz4Q4yjWxeEcDJ8gemjuCSix3F8q9YEZN5+FIkO43TcP/8zTTe06EjezVl9qJv+tZkLy/GOpV3PIZwlQ5rHZzZcDwfJ21GS4rNPQZfKsMyQBX6Dfnp6mNbpO1FFgTfWEtTgArbQs8Za95IGdDG1xT8asx/hWHPoSiTCuQXvacI1DNpHhM6AWKaH636vv6QeuuBlz2n26zw53t1N3/6OIfVQLRyJ9Lwy9VJRZ/EAdpSKggdQ3K7uf2MVbub+jdor6IyheKKFRbvXFDl1OYMFUqKPnarR/O9jBGQIktZUwIRiyFIkPbZwzWoGVb28BtL0U0gwFbu/wEWzCJNA4+QkSMNIhKU6YD1g6CpTFb3cThcSbeOa4XDyjpZ1oTTsY1s+Z0L0vIUeAF6VJST6ybipn5X8JB1oxA0pEyx1Ft+redgkmDx+YQionH12XUmshwdNDtburN7+gTaLMPTyOMIr5HlYMsCAwEAAQ==";

        /**
         * **********************certificate authentication
         * **********************************************
         */
        System.out.println("Starting CA and server authentication! ");

        System.out.println("Verifying Server Name:--------------------------------------------------------------------------------------------------------------------------------");

        if (identity.equals(ExpectedServerName)) {
            System.out.print("Server Name in the certificate matched with the expected server name! \n");
        } else {
            System.out.print("Server Name is wrong!\n");
        }

        System.out.println("Verifying CA name:------------------------------------------------------------------------------------------------------------------------------------");

        if (CertificateCAname.equals(trusted_CAname)) {
            System.out.print("Certificate Authority Name present in the trusted list of Certificate Authorities! \n");
        } else {
            System.out.print("Certificate Authority name is wrong!\n");
        }

        System.out.println("Verifying Signature:----------------------------------------------------------------------------------------------------------------------------------");

        if (!certificateAuthority.ValidateCA_Authentication(CA_PublicKey, identity1, hashcode)) {
            throw new Exception("Failed to authenticate certificate!");
        } else {
            System.out.print("Signature is Valid....\n");
        }

        //uses the java framwork and the inbuilt signature 
        if (!certificateAuthority.verify(identity1, certificateAuthority.sign(identity1, certificateAuthority.CA_PR), certificateAuthority.CA_PU)) {
            throw new Exception("Failed to authenticate certificate!");
        } else {
            System.out.print("Signature is Valid\n");
        }

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println(" Completed Phase 2 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        /**
         * ********************************************
         * Send server the pre master secret by encrypting it with the public
         * key retrieved from the certificate
         * ******************************************************
         */
        System.out.println("Send server the pre_master_secret by encrypting it with the Server public key retrieved from the certificate:----------------------------------------");
        System.out.println("RSA algorithm is used for key change");

        byte[] b_plaintext = pre_master_secret.getBytes();
        Cipher encrypt = Cipher.getInstance("RSA");

        encrypt.init(Cipher.ENCRYPT_MODE, PU_a);

        byte[] b_ciphertext = encrypt.doFinal(b_plaintext);
        String ciphertext = Base64.getEncoder().encodeToString(b_ciphertext);
        out.println(ciphertext);
        out.flush();
        client_packet2 = ciphertext;

        /**
         * **********************
         * creating 4 sub keys after computing the master key from
         * pre-master-secret key **********************************************
         */
        System.out.println("Caculating master_secret and then creating 4 sub keys:-----------------------------------------------------------------------------------------------");

        int master_secret = (5896 * Nc * Ns);
        System.out.println("Master Secret: " + master_secret);

        if (master_secret < 0) {
            master_secret = master_secret * (-1);
        }
        Key2 = master_secret % 8642;
        System.out.println("Key2: " + Key2);
        Key4 = master_secret % 8642;
        System.out.println("Key4: " + Key4);

        Key1 = master_secret % 3456;
        System.out.println("Key1: " + Key1);
        Key3 = master_secret % 3456;
        System.out.println("Key3: " + Key3);

        String x = "" + Key2;
        int k;
        if (x.length() != 4) {
            for (k = x.length(); k <= 4; k++) {
                x = x + "8";
            }

        }

        String desKey = x + x + x + x;
        int x1 = (desKey.getBytes()).length * 8;
        System.out.print("desKey: " + x1 + "\n");

        byte[] keyBytes = DatatypeConverter.parseHexBinary(desKey);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        SecretKey keyMc = factory.generateSecret(new DESKeySpec(keyBytes)); //encryption

        // covert 2   
        String desKey1 = x + x + x + x;
        byte[] keyBytes1 = DatatypeConverter.parseHexBinary(desKey1);

        SecretKeyFactory factory1 = SecretKeyFactory.getInstance("DES");
        SecretKey keyMs = factory1.generateSecret(new DESKeySpec(keyBytes1)); //decryption

        //3des
        String desKey0 = x + x + x + x;
        for (int a = 0; a < 2; a++) {
            desKey0 = desKey0 + desKey0;
        }
        byte[] keyBytes0 = DatatypeConverter.parseHexBinary(desKey0);

        SecretKeyFactory factory0 = SecretKeyFactory.getInstance("DESede");
        SecretKey keyMc1 = factory0.generateSecret(new DESedeKeySpec(keyBytes0)); //

        SecretKeyFactory factory11 = SecretKeyFactory.getInstance("DESede");
        SecretKey keyMs1 = factory11.generateSecret(new DESedeKeySpec(keyBytes0)); //

        //convert 3
        String desKey2 = x + x + x + x;
        byte[] keyBytes2 = DatatypeConverter.parseHexBinary(desKey2);

        SecretKeyFactory factory2 = SecretKeyFactory.getInstance("DES");
        SecretKey keyKc = factory2.generateSecret(new DESKeySpec(keyBytes2)); //validation send

        //convert 4
        String desKey3 = x + x + x + x;
        byte[] keyBytes3 = DatatypeConverter.parseHexBinary(desKey3);

        SecretKeyFactory factory3 = SecretKeyFactory.getInstance("DES");
        SecretKey keyKs = factory3.generateSecret(new DESKeySpec(keyBytes1));   //validation received

        System.out.println("");
        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 3 Implementation");
        System.out.println("***************************************************************************************************************************************************");
        System.out.println("");

        System.out.println("Sending client  Change Cipher Spec:-------------------------------------------------------------------------------------------------------------------");

        // Recieve server MAC
        String change_cipher_spec = "1";
        out.println(change_cipher_spec);
        out.flush();

        System.out.println("Sending Client Finished Message:----------------------------------------------------------------------------------------------------------------------");

        String mac_send = "" + client_packet1 + server_packet1 + client_packet2 + BigInteger.valueOf(Key2);
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

        System.out.println("Client MAC: " + mac);

        server_packet2 = in.readLine();
        System.out.println("Server MAC: " + server_packet2);

        if (!server_packet2.equals(mac)) {
            throw new Exception("MACs do not match!");
        }
        String server_change_cipher_spec = in.readLine();
        System.out.print("Server change_cipher_spec: " + server_change_cipher_spec + "\n");

        // Connection Sucess!
        System.out.println("Connected");

        System.out.println("**************************************************************************************************************************************************");
        System.out.println("Completed Phase 4 Implementation");
        System.out.println("***************************************************************************************************************************************************");

        System.out.println("*********************************************************************");
        System.out.println("SSL HANDSHAKE ESTABLISHED SUCCESSFULLY");
        System.out.println("*********************************************************************");

        try {

            userInput = new BufferedReader(new InputStreamReader(System.in));

            Cipher encrypt1 = Cipher.getInstance("DES");
            Cipher decrypt1 = Cipher.getInstance("DES");
            encrypt1.init(Cipher.ENCRYPT_MODE, keyMc);
            decrypt1.init(Cipher.DECRYPT_MODE, keyMs);

            Cipher encrypt2 = Cipher.getInstance("DESede");
            Cipher decrypt2 = Cipher.getInstance("DESede");
            encrypt2.init(Cipher.ENCRYPT_MODE, keyMc1);
            decrypt2.init(Cipher.DECRYPT_MODE, keyMs1);

            String s_ciphertext = "";
            String s_plaintext = "";

            //Receive client messages and echo
            String plaintext_send = "";
            String receiveMessage, sendMessage;
            while (true) {

                if ((receiveMessage = in.readLine()) != "EXIT") {

                    System.out.print("\n");

                    if (receiveMessage.equals("EXIT")) {
                        break;
                    }
                    System.out.print("\n");
                    System.out.print("CIPHERTEXT RECEIVED: " + receiveMessage);
                    switch (write_algo) {
                        case "DES":
                            b_ciphertext = Base64.getDecoder().decode(receiveMessage);

                            b_plaintext = decrypt1.doFinal(b_ciphertext);
                            s_plaintext = new String(b_plaintext);

                            System.out.print("\n");
                            System.out.println("DECRYPTED MESSAGE>>>>>>>>>>>>>>>:" + s_plaintext);
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
                    System.out.print("\n");

                    int j1;

                    System.out.println("MESSAGE AUTHENTICATION CODE RECEIVED: " + receiveMessage);

                    String messagehashencrypted = receiveMessage;

                    switch (mac_algo) {
                        case "SHA-1":
                            MAC m = new MAC();
                            boolean result = m.ValidateMac(s_plaintext, messagehashencrypted, mac_algo, keyKc);
                            if (result == true) {
                                System.out.print("MESSAGE AUTHENTICATION SUCCESSFUL\n");
                            } else {
                                System.out.print("Validation failed\n");
                            }
                            break;
                        case "MD5":
                            MAC m1 = new MAC();
                            boolean result1 = m1.ValidateMac(s_plaintext, messagehashencrypted, mac_algo, keyKc);
                            if (result1 == true) {
                                System.out.print("Validation passed");
                            } else {
                                System.out.print("Validation failed");
                            }
                            break;
                    }

                }

                System.out.print("\n");
                System.out.print("Type in to send message.\n");
                System.out.print("Type 'EXIT' to end the program.\n");
                System.out.print("Enter:");

                sendMessage = userInput.readLine();

                if (sendMessage.equals("EXIT")) {
                    out.println("EXIT");
                    out.flush();
                    System.out.println("**************************************************************************************************************************************************");
                    System.out.println("SSL Record Layer Implementated Successfully ");
                    System.out.println("***************************************************************************************************************************************************");
                    break;
                }

                if (!sendMessage.equals("EXIT")) {

                    switch (write_algo) {
                        case "DES":
                            byte[] b_plaintext_send = sendMessage.getBytes("UTF8");
                            byte[] b_ciphertext_send = encrypt1.doFinal(b_plaintext_send);
                            String ciphertext_send = Base64.getEncoder().encodeToString(b_ciphertext_send);

                            //Send message
                            out.println(ciphertext_send);
                            out.flush();

                            //Debugging
                            System.out.print("\n");
                            System.out.println("CIPHERTEXT SEND: " + ciphertext_send + "\n");
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
                    switch (mac_algo) {
                        case "SHA-1":
                            MAC m = new MAC();

                            String encrypedMacMessage = m.mac(sendMessage, mac_algo, keyKc);
                            System.out.print("\n");
                            System.out.print("MESSAGE AUTHENTICATION CODE SEND: " + encrypedMacMessage + "\n");

                            out.println(encrypedMacMessage);
                            out.flush();
                            System.out.print("sucessfully send \n");
                            break;
                        case "MD5":
                            MAC m1 = new MAC();
                            String encrypedMacMessage2 = m1.mac(sendMessage, mac_algo, keyKc);
                            System.out.print("MESSAGE AUTHENTICATION CODE SEND: " + encrypedMacMessage2 + "\n");
                            out.println(encrypedMacMessage2);
                            out.flush();
                            System.out.print("sucessfully send \n");
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
