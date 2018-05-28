package org.shenjia.chnsm;

import org.bouncycastle.util.encoders.Hex;

public class SM4Utils {

	private String secretKey;
	private String iv;
	private boolean hexString = true;

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public boolean isHexString() {
		return hexString;
	}

	public void setHexString(boolean hexString) {
		this.hexString = hexString;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	public String ecbEncrypt(String plainText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.mode = SM4.ENCRYPT;

			byte[] keyBytes, dataBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				dataBytes = Hex.decode(plainText);
			} else {
				keyBytes = secretKey.getBytes();
				dataBytes = plainText.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.setEncryptKey(ctx, keyBytes);
			byte[] encrypted = sm4.ecbPadCrypt(ctx, dataBytes);
			return Hex.toHexString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String ecbDecrypt(String cipherText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.mode = SM4.DECRYPT;

			byte[] keyBytes, dataBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				dataBytes = Hex.decode(cipherText);
			} else {
				keyBytes = secretKey.getBytes();
				dataBytes = cipherText.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.setDecryptKey(ctx, keyBytes);
			byte[] decrypted = sm4.ecbPadCrypt(ctx, dataBytes);
			return Hex.toHexString(decrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String cbcEncrypt(String plainText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.mode = SM4.ENCRYPT;

			byte[] keyBytes, ivBytes, dataBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				ivBytes = Hex.decode(iv);
				dataBytes = Hex.decode(plainText);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
				dataBytes = plainText.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.setEncryptKey(ctx, keyBytes);
			byte[] encrypted = sm4.cbcPadCrypt(ctx, ivBytes, dataBytes);
			return Hex.toHexString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String cbcDecrypt(String cipherText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.mode = SM4.DECRYPT;

			byte[] keyBytes, ivBytes, dataBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				ivBytes = Hex.decode(iv);
				dataBytes = Hex.decode(cipherText);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
				dataBytes = cipherText.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.setDecryptKey(ctx, keyBytes);
			byte[] decrypted = sm4.cbcPadCrypt(ctx, ivBytes, dataBytes);
			return Hex.toHexString(decrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
