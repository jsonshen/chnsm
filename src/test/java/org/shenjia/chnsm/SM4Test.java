package org.shenjia.chnsm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.shenjia.chnsm.SM4Utils;

import java.io.IOException;

public class SM4Test {

	@Test
	public void testSM4() throws IOException {
		String plainText = "abcd";

		SM4Utils sm4 = new SM4Utils();
		sm4.setSecretKey("JeF8U9wHFOMfs2Y8");
		sm4.setHexString(false);

		System.out.println("ECB模式");
		String cipherText = sm4.encryptECB(plainText);
		System.out.println("密文: " + cipherText);

		String s1 = sm4.decryptECB(cipherText);
		System.out.println("明文: " + s1);
		Assertions.assertEquals(s1, plainText);

		System.out.println("CBC模式");
		sm4.setIv("UISwD9fW6cFh9SNS");
		cipherText = sm4.encryptCBC(plainText);
		System.out.println("密文: " + cipherText);

		String s2 = sm4.decryptCBC(cipherText);
		System.out.println("明文: " + s2);

		Assertions.assertEquals(s2, plainText);
	}
}
