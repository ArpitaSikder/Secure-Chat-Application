
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author arpitasikder
 */
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class CA {

    static PublicKey CA_PU;
    static PrivateKey CA_PR;
    BigInteger hash;

    static byte[] x;
    String hashAlgorithm;
    String publicKeyAlgorithm;

    public CA() throws NoSuchAlgorithmException, Exception {

        KeyPairGenerator CA_key = KeyPairGenerator.getInstance("RSA");
        CA_key.initialize(4096, new SecureRandom());
        KeyPair keyPair = CA_key.generateKeyPair();
        CA_PU = keyPair.getPublic();
        CA_PR = keyPair.getPrivate();

        hash = new BigInteger("13");
        hashAlgorithm = "SHA-1";
        publicKeyAlgorithm = "RSA";

    }

    public String CertificateEncrypt(String identity) throws Exception {

        String CA_P = "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";
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(CA_P.getBytes()));
        KeyFactory keyFactory = null;
        keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        md.update(identity.getBytes());
        byte[] hashValue = md.digest();
        System.out.print("\n");

        Cipher publicKeyEncryption = Cipher.getInstance(publicKeyAlgorithm);
        publicKeyEncryption.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encryptedHash = publicKeyEncryption.doFinal(hashValue);
        String encryptedHashString = new String(Base64.getEncoder().encode(encryptedHash));

        System.out.print("AterEncryption: " + encryptedHashString + "\n");
        return encryptedHashString;

    }

    public Boolean ValidateCA_Authentication(String CA_PU_key, String identity, String hashcode) throws Exception { //hashcode wrong
        boolean validate = false;

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(CA_PU_key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey PUKey = keyFactory.generatePublic(keySpec);

        System.out.print("AterEncryption: " + hashcode + "\n");

        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        md.update(identity.getBytes());
        byte[] expectedHash = md.digest();

        String expectedHashString = new String(Base64.getEncoder().encode(expectedHash));

        System.out.print("AferDecryption: " + expectedHashString + "\n");

        byte[] decodedSignature = Base64.getDecoder().decode(hashcode.getBytes());
        Cipher publicKeyEncryption = Cipher.getInstance(publicKeyAlgorithm);
        publicKeyEncryption.init(Cipher.DECRYPT_MODE, PUKey);

        byte[] decryptedHash = publicKeyEncryption.doFinal(decodedSignature);

        String decryptredHashString = new String(Base64.getEncoder().encode(decryptedHash));

        if (decryptredHashString.equals(expectedHashString)) {
            System.out.println("Signature is valid...");
            validate = true;
        }
        return validate;

    }

    public static byte[] encrypt(String plainText, PrivateKey PU) throws Exception {

        Cipher encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, PU);
        byte[] encoded = encrypt.doFinal(plainText.getBytes("UTF-8"));

        return encoded;
    }

    public static String decrypt(byte[] arr, PublicKey PR) throws Exception {

        Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decrypt.init(Cipher.DECRYPT_MODE, PR);
        byte[] arr1 = decrypt.doFinal(arr);
        return new String(arr1);
    }

    public String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature DigitalSignature = Signature.getInstance("SHA256withRSA");
        DigitalSignature.initSign(privateKey);
        DigitalSignature.update(plainText.getBytes("UTF8"));

        byte[] DigitalSign = DigitalSignature.sign();

        return Base64.getEncoder().encodeToString(DigitalSign);
    }

    public boolean verify(String plainText, String DigitalSign, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF8"));

        byte[] DigitalSignBytes = Base64.getDecoder().decode(DigitalSign);

        return publicSignature.verify(DigitalSignBytes);
    }

}
