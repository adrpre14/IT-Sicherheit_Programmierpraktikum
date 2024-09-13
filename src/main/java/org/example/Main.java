package org.example;

import com.macasaet.fernet.Key;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws IOException {
//        File file = new File("src/main/resources/example.txt");
//        XorSecretSharing xorSecretSharing = new XorSecretSharing(1000);
//        byte[] secret = Files.readAllBytes(file.toPath());
//
//        byte[][] shares = xorSecretSharing.share(secret);
//        for (int i = 0; i < shares.length; i++) {
//            Files.write(new File("src/main/resources/share" + i + ".txt").toPath(), shares[i]);
//        }
//        byte[][] fileShares = new byte[shares.length][];
//        for (int i = 0; i < shares.length; i++) {
//            fileShares[i] = Files.readAllBytes(new File("src/main/resources/share" + i + ".txt").toPath());
//        }
//        byte[] reconstructedSecret = xorSecretSharing.combine(fileShares);
//        Files.write(new File("src/main/resources/reconstructed.txt").toPath(), reconstructedSecret);

//        BigInteger secret = new
//                BigInteger("3813930054453974457568485845152728895766160052607701932613851219066318585698326638746441282528502371871549");
//        ShamirSecretSharing shamirSecretSharing = new ShamirSecretSharing(40, 50);
//        ShamirShare[] shares = shamirSecretSharing.share(secret);
//        BigInteger reconstructedSecret = shamirSecretSharing.combine(
//                shares
//        );
//        System.out.println(secret);
//        System.out.println(reconstructedSecret);

//        File file = new File("src/main/resources/file");
//        Key key = Encryption.generateKey();
//        Encryption.encryptFile(file, key);
//        Encryption.decryptFile(new File("src/main/resources/file.enc"), key);

        File file = new File("src/main/resources/file");
        Encryption.encryptFileWithShares(file);
        File[] sharedKeys = new File[4];
        for (int i = 0; i < sharedKeys.length; i++) {
            sharedKeys[i] = new File("src/main/resources/file.key." + (i + 1));
        }

        Encryption.descryptFileWithShares(new File("src/main/resources/file.enc"), sharedKeys);
    }
}