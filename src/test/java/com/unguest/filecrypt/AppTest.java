package com.unguest.filecrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Unit test for simple App.
 */
class AppTest {
    /**
     * Rigorous Test.
     */
    @Test
    void testApp() {
        assertEquals(1, 1);
    }

    @Test
    void givenString_whenEncrypt_thenSuccess() throws NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        String input = "unguest";
        SecretKey key = AESUtil.generateKey(128);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(AESUtil.generateIv());
        String cipherText = AESUtil.encrypt(input, key, ivParameterSpec);
        String plainText = AESUtil.decrypt(cipherText, key, ivParameterSpec);
        Assertions.assertEquals(input, plainText);
    }
}
