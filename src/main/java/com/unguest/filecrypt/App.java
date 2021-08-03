package com.unguest.filecrypt;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public final class App {

    final short version = 0;
    final short update = 1;
    final short patch = 0;

    static Scanner scanner = new Scanner(System.in);

    private App() {
    }

    /**
     * Says hello to the world.
     * 
     * @param args The arguments of the program.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws DecoderException
     * @throws IOException
     */
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException,
            IllegalBlockSizeException, DecoderException, IOException {
        menu();
    }

    public static void menu() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException,
            IOException, DecoderException {
        short choice = 0;

        while (choice != 3) {
            System.out.println("1 - Encrypt a file");
            System.out.println("2 - Decrypt a file");
            System.out.println("3 - Exit");

            System.out.print("FileCrypt > ");

            choice = scanner.nextShort();
            scanner.nextLine(); // Consume the '/n' and avoid problems

            switch (choice) {
                case 1:
                    userEncryptFile();
                    break;
                case 2:
                    userDecryptFile();
                    break;
                case 3:
                    scanner.close();
                    System.out.println("Thank you ~~~ github.com/unguest");
                    break;
                default:
                    System.out.println("Unknown input...");
            }
        }
    }

    public static void userEncryptFile()
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {

        System.out.print("File to encrypt : ");
        String filename = scanner.nextLine();
        System.out.print("Password : ");
        String password = scanner.nextLine();

        String salt = AESUtil.generateSalt(32);
        byte[] iv = AESUtil.generateIv();
        IvParameterSpec ivObj = new IvParameterSpec(iv);
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);

        File clearFile = new File(filename);
        File encFile = new File(filename + ".enc");

        AESUtil.encryptFile(key, ivObj, clearFile, encFile);

        FileUtil.writeFile(filename + ".enc.inf",
                AESUtil.fileEncFormatForFile(new String(Hex.encodeHexString(iv)), salt));

    }

    public static void encryptStringToFile(String filename, String password, String content)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        String salt = AESUtil.generateSalt(32);
        byte[] iv = AESUtil.generateIv();
        IvParameterSpec ivObj = new IvParameterSpec(iv);
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);
        String cipherText = AESUtil.encrypt(content, key, ivObj);
        FileUtil.writeFile(filename, AESUtil.formatForFile(cipherText, new String(Hex.encodeHex(iv)), salt));
    }

    public static void userDecryptFile() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException,
            DecoderException, IOException {

        System.out.print("File to encrypt : ");
        String filename = scanner.nextLine();
        System.out.print("Password : ");
        String password = scanner.nextLine();

        File encFile = new File(filename);
        File clearFile = new File(filename + ".dec");

        String[] infos = AESUtil.fileEncFormatFromFile(FileUtil.readFile(filename + ".inf"));

        String salt = infos[1];

        byte[] iv = Hex.decodeHex(infos[0].toCharArray());
        IvParameterSpec ivObj = new IvParameterSpec(iv);
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);
        AESUtil.decryptFile(key, ivObj, encFile, clearFile);
    }

    public static void decryptStringToFile(String filename, String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, DecoderException {

        String[] elements = AESUtil.formatFromFile(FileUtil.readFile(filename));
        String cipherText = elements[0];
        byte[] iv = Hex.decodeHex(elements[1].toCharArray());
        String salt = elements[2];

        IvParameterSpec ivObj = new IvParameterSpec(iv);
        SecretKey key = AESUtil.getKeyFromPassword(password, salt);
        FileUtil.writeFile(filename + ".dec", AESUtil.decrypt(cipherText, key, ivObj));
    }
}