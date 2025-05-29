package org.tool.passfort.util.encrypt;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ShuffleAESEncryptionTest {
    private final static AesUtil aesUtil = new AesUtil();

    @Test
    public void decryptTest() throws Exception {
        String base64Encrpted = "/SLfhH1D8fhwDub7jAD/l9MyQ6AhqYIl57/YYNlx/akVZ/pXjdy6zDgXza5FR4eFMHC3uEzHEMF3sIJoXrxwSQ==";
        String password = "qwer";

        System.out.println("Shuffled encryption:" + base64Encrpted);

        // Base64 解码
        byte[] shuffledEncryptedData = Base64.getDecoder().decode(base64Encrpted);
        byte[] unshuffledEncryptedData = ShuffleEncryption.shuffleDecrypt(shuffledEncryptedData, 8, new int[]{7, 2, 5, 0, 3, 6, 1, 4});

        // unshuffled data
        System.out.println("Unshuffled encryption:" + new String(Base64.getEncoder().encode(unshuffledEncryptedData)));

        // AES decrypt
        String decryptedData = aesUtil.decrypt(unshuffledEncryptedData);
        System.out.println("Decrypted data:" + decryptedData);
        assertEquals(password, decryptedData, "Decrypted data should match the original data");
    }
}
