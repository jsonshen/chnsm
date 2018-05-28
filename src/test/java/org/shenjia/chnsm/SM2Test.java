package org.shenjia.chnsm;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SM2Test {

	@Test
	public void testSM2() throws Exception {
		String plainText = "MESSAGE DIGEST";
		byte[] sourceData = plainText.getBytes();

		// 国密规范测试私钥
		String prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
		String prikS = new String(Base64.encode(Hex.decode(prik)));
		System.out.println("prikS: " + prikS);

		// 国密规范测试用户ID
		String uid = "ALICE123@YAHOO.COM";
		System.out.println("ID: " + uid);

		System.out.println("签名: ");
		byte[] c = SM2Utils.sign(uid.getBytes(), Base64.decode(prikS.getBytes()), sourceData);
		System.out.println("sign: " + Hex.toHexString(c));

		// 国密规范测试公钥
		String pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
		String pubkS = new String(Base64.encode(Hex.decode(pubk)));
		System.out.println("pubkS: " + pubkS);

		System.out.println("验签: ");
		boolean vs = SM2Utils.verifySign(uid.getBytes(), Base64.decode(pubkS.getBytes()), sourceData, c);
		System.out.println("验签结果: " + vs);
		Assertions.assertTrue(vs);

		System.out.println("加密: ");
		byte[] cipherText = SM2Utils.encrypt(Base64.decode(pubkS.getBytes()), sourceData);
		System.out.println(new String(Base64.encode(cipherText)));

		System.out.println("解密: ");
		String s1 = new String(SM2Utils.decrypt(Base64.decode(prikS.getBytes()), cipherText));
		System.out.println(s1);

		Assertions.assertEquals(s1, plainText);
	}
}
