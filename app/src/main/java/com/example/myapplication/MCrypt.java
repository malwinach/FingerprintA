package com.example.myapplication;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.widget.Toast;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;


public class MCrypt {

    public static Cipher CIPHER_AES;
    public String alias = "kluczyk";

    @RequiresApi(api = Build.VERSION_CODES.M)
    public MCrypt() throws NoSuchProviderException, NoSuchAlgorithmException {

        try {
            CIPHER_AES = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private Key genereteOrGetKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias(alias)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

                keyGenerator.init(new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build());

                return keyGenerator.generateKey();
            } else {
                return keyStore.getKey(alias, null);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }


    private byte[] encrypt(Key key, String plainText, String ivFilename){
        byte[] plainTextAsByteArray = plainText.getBytes();
        byte[] encryptedText;
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_AES);
            //System.out.println("Cipher created");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            //System.out.println("Cipher init");
            encryptedText = cipher.doFinal(plainTextAsByteArray);
            //System.out.println("encrypted");
            //System.out.println("IV: " + Arrays.toString(cipher.getIV()));
            Save(ivFilename, Base64.encodeToString(cipher.getIV(), Base64.DEFAULT));

            //System.out.println("ENCRYPTED TEXT " + Arrays.toString(encryptedText));
            return encryptedText;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("encrypt");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            System.out.println("encrypt");

        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            System.out.println("encrypt");

        } catch (BadPaddingException e) {
            e.printStackTrace();
            System.out.println("encrypt");

        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
            System.out.println("encrypt");

        }

        return null;
    }

    private byte[] decrypt(Key key, byte[] encryptedText, String ivFilename){

        try{
            Cipher cipher = Cipher.getInstance(CIPHER_AES);
            //System.out.println("D CIPHER INST");
            byte[] iv = Base64.decode(Open(ivFilename), Base64.DEFAULT);
            //System.out.println("FILE IV " + iv);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            //System.out.println("D CIPHER INIT");
            byte[] plaintText = cipher.doFinal(encryptedText);
            //System.out.println("DECRYPTED" + Arrays.toString(plaintText));
            return plaintText;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String byteArrayToHexString(byte[] array) {
        StringBuffer hexString = new StringBuffer();
        for (byte b : array) {
            int intVal = b & 0xff;
            if (intVal < 0x10)
                hexString.append("0");
            hexString.append(Integer.toHexString(intVal));
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String str) {
        if (str == null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {

            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i = 0; i < len; i++) {
                buffer[i] = (byte) Integer.parseInt(
                        str.substring(i * 2, i * 2 + 2), 16);

            }
            return buffer;
        }
    }

    private static String padString(String source) {
        char paddingChar = 0;
        int size = 16;
        int x = source.length() % size;
        int padLength = size - x;
        for (int i = 0; i < padLength; i++) {
            source += paddingChar;
        }
        return source;
    }

    public static String HexToASCII(String hex) {

        if(hex.length()%2!=0){
            System.err.println("Invlid hex string.");
        }

        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < hex.length(); i = i + 2) {
            // Step-1 Split the hex string into two character group
            String s = hex.substring(i, i + 2);
            // Step-2 Convert the each character group into integer using valueOf method
            int n = Integer.valueOf(s, 16);
            // Step-3 Cast the integer value to char
            builder.append((char)n);
        }

        return builder.toString();
    }
}
