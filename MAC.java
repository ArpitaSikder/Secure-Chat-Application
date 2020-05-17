/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author arpitasikder
 */
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MAC {

    public MAC() {
    }

    public String mac(String msg, String hash, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        System.out.print("hashValue: " + hash + "\n");
        String key = Base64.getEncoder().encodeToString(k.getEncoded());
        msg = "" + msg + key;
        MessageDigest md = MessageDigest.getInstance(hash);
        md.update(msg.getBytes());
        byte[] hashValue = md.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : hashValue) {
            sb.append(String.format("%02X", b));
        }

        String sb1 = "" + sb;
        return sb1;

    }

    public Boolean ValidateMac(String msg, String hashcode, String hash, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

        boolean v = false;

        System.out.print("hash: " + hash + "\n");
        String key = Base64.getEncoder().encodeToString(k.getEncoded());
        msg = "" + msg + key;
        MessageDigest md = MessageDigest.getInstance(hash);
        md.update(msg.getBytes());
        byte[] expectedHash = md.digest();

        StringBuilder sb = new StringBuilder();
        for (byte b : expectedHash) {
            sb.append(String.format("%02X", b));
        }

        String sb1 = "" + sb;

        System.out.print("\n");
        System.out.print("MAC RECEIVED: " + hashcode + "\n");
        System.out.print("MAC CREATED: " + sb1 + "\n");
        if (sb1.equals(hashcode)) {
            System.out.println("Validation passed...");
            v = true;
        }
        return v;

    }

}
