package org.shenjia.chnsm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.shenjia.chnsm.SM4Utils;

import java.io.IOException;

public class SM4Test {

	@Test
	public void testSM4() throws IOException {
		String key = "01010101010101010101010101010101";
		String plainText = "31680d0d6bcd9bc131680d0d6bcd9bc1";

		SM4Utils sm4 = new SM4Utils();
		sm4.setSecretKey(key);
		sm4.setHexString(true);

		System.out.println("ECB模式");
		String cipherText = sm4.ecbEncrypt(plainText);
		System.out.println("密文: " + cipherText);

		String s1 = sm4.ecbDecrypt(cipherText);
		System.out.println("明文: " + s1);
		Assertions.assertEquals(s1, plainText);
		
		System.out.println("CBC模式");
		sm4.setIv("01010101010101010101010101010101");
		cipherText = sm4.cbcEncrypt(plainText);
		System.out.println("密文: " + cipherText);

		String s2 = sm4.cbcDecrypt(cipherText);
		System.out.println("明文: " + s2);
		Assertions.assertEquals(s2, plainText);
	}
}
