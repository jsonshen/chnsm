package org.shenjia.chnsm;

import org.bouncycastle.util.encoders.Hex;

public class SM4Utils {

	private String charset = "GBK";
	private String secretKey;
	private String iv;
	private boolean hexString = false;
	
	public String getCharset() {
		return charset;
	}

	public void setCharset(String charset) {
		this.charset = charset;
	}

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

	public String encryptECB(String plainText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
			} else {
				keyBytes = secretKey.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_ecb(ctx, plainText.getBytes(charset));
			return Hex.toHexString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decryptECB(String cipherText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
			} else {
				keyBytes = secretKey.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_ecb(ctx, Hex.decode(cipherText));
			return new String(decrypted, charset);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String encryptCBC(String plainText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_ENCRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				ivBytes = Hex.decode(iv);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_enc(ctx, keyBytes);
			byte[] encrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, plainText.getBytes(charset));
			return Hex.toHexString(encrypted);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decryptCBC(String cipherText) {
		try {
			SM4Context ctx = new SM4Context();
			ctx.isPadding = true;
			ctx.mode = SM4.SM4_DECRYPT;

			byte[] keyBytes;
			byte[] ivBytes;
			if (hexString) {
				keyBytes = Hex.decode(secretKey);
				ivBytes = Hex.decode(iv);
			} else {
				keyBytes = secretKey.getBytes();
				ivBytes = iv.getBytes();
			}

			SM4 sm4 = new SM4();
			sm4.sm4_setkey_dec(ctx, keyBytes);
			byte[] decrypted = sm4.sm4_crypt_cbc(ctx, ivBytes, Hex.decode(cipherText));
			return new String(decrypted, charset);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
