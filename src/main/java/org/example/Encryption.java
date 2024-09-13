package org.example;

import com.macasaet.fernet.Key;
import com.macasaet.fernet.Token;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;

public class Encryption {
    private static final BytesValidator validator = new BytesValidator() {};
    private static final ShamirSecretSharing sharing = new ShamirSecretSharing(2, 4);

    public static Key generateKey() {
        byte[] keyBytes = new byte[32];

        new SecureRandom().nextBytes(keyBytes);
        return new Key(keyBytes);
    }

    public static void encryptFile(File file, Key key) throws IOException {
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        Token token = Token.generate(key, fileBytes);
        File encryptedFile = new File("src/main/resources/" + file.getName() + ".enc");
        token.writeTo(Files.newOutputStream(encryptedFile.toPath()));
    }

    public static void decryptFile(File file, Key key) throws IOException {
        byte[] encryptedBytes = Files.readAllBytes(file.toPath());
        Token token = Token.fromBytes(encryptedBytes);
        byte[] decryptedBytes = validator.validateAndDecrypt(key, token);
        File decryptedFile = new File("src/main/resources/" + file.getName().replace(".enc", ".dec"));
        Files.write(decryptedFile.toPath(), decryptedBytes);
    }

    // encrypts a file and separates the key into n shares
    public static void encryptFileWithShares(File file) throws IOException {
        Key key = generateKey();
        encryptFile(file, key);
        byte[] keyBytes = Base64.getUrlDecoder().decode(key.serialise());
        BigInteger keyInt = BigIntegerUtils.fromUnsignedByteArray(keyBytes);
        ShamirShare[] shares = sharing.share(keyInt);
        for (int i = 0; i < shares.length; i++) {
            shares[i].writeTo(Files.newOutputStream(new File("src/main/resources/" + file.getName() + ".key." + (i + 1)).toPath()));
        }
    }

    public static void descryptFileWithShares(File file, File[] sharedKeys) throws IOException {
        byte[] keyBytes;
        ShamirShare[] shares = new ShamirShare[sharing.getT()];
        for (int i = 0; i < sharing.getT(); i++) {
            int randomIndex = new SecureRandom().nextInt(sharedKeys.length);
            File sharedKey = sharedKeys[randomIndex];
            shares[i] = ShamirShare.fromStream(Files.newInputStream(sharedKey.toPath()));
        }
        BigInteger keyInt = sharing.combine(shares);
        keyBytes = BigIntegerUtils.toUnsignedByteArray(keyInt);
        String keyString = Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);
        Key key = new Key(keyString);
        decryptFile(file, key);
    }

}
