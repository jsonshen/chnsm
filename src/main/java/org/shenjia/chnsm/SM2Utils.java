package org.shenjia.chnsm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;

public class SM2Utils {
	
	public static byte[] encrypt(byte[] publicKey, byte[] data) throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

		SM3Cipher cipher = new SM3Cipher();
		SM2 sm2 = SM2.instance();
		ECPoint userKey = sm2.ecCurve.decodePoint(publicKey);

		ECPoint c1 = cipher.initEncrypt(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.dofinal(c3);

		ASN1Integer x = new ASN1Integer(c1.getAffineXCoord().toBigInteger());
		ASN1Integer y = new ASN1Integer(c1.getAffineYCoord().toBigInteger());
		DEROctetString derDig = new DEROctetString(c3);
		DEROctetString derEnc = new DEROctetString(source);
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(x);
		v.add(y);
		v.add(derDig);
		v.add(derEnc);
		DERSequence seq = new DERSequence(v);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DEROutputStream dos = new DEROutputStream(bos);
		dos.writeObject(seq);
		return bos.toByteArray();
	}

	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}

		byte[] enc = new byte[encryptedData.length];
		System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);

		SM2 sm2 = SM2.instance();
		BigInteger userD = new BigInteger(1, privateKey);

		ByteArrayInputStream bis = new ByteArrayInputStream(enc);
		ASN1Primitive derObj;
		try(ASN1InputStream dis = new ASN1InputStream(bis);) {
			derObj = dis.readObject();
		}
		ASN1Sequence asn1 = (ASN1Sequence) derObj;
		ASN1Integer x = (ASN1Integer) asn1.getObjectAt(0);
		ASN1Integer y = (ASN1Integer) asn1.getObjectAt(1);
		ECPoint c1 = sm2.ecCurve.createPoint(x.getValue(), y.getValue());

		SM3Cipher cipher = new SM3Cipher();
		cipher.initDecrypt(userD, c1);
		DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
		enc = data.getOctets();
		cipher.decrypt(enc);
		byte[] c3 = new byte[32];
		cipher.dofinal(c3);
		return enc;
	}

	public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (sourceData == null || sourceData.length == 0) {
			return null;
		}

		SM2 sm2 = SM2.instance();
		BigInteger uid = new BigInteger(privateKey);

		ECPoint userKey = sm2.ecPoint.multiply(uid);

		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);

		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		SM2Result result = new SM2Result();
		sm2.sm2Sign(md, uid, userKey, result);

		ASN1Integer d_r = new ASN1Integer(result.r);
		ASN1Integer d_s = new ASN1Integer(result.s);
		ASN1EncodableVector v2 = new ASN1EncodableVector();
		v2.add(d_r);
		v2.add(d_s);
		ASN1Primitive sign = new DERSequence(v2);
		byte[] signdata = sign.getEncoded();
		return signdata;
	}

	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] uid, byte[] publicKey, byte[] sourceData, byte[] signData)
			throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return false;
		}

		if (sourceData == null || sourceData.length == 0) {
			return false;
		}

		SM2 sm2 = SM2.instance();
		ECPoint userKey = sm2.ecCurve.decodePoint(publicKey);

		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(uid, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		ByteArrayInputStream bis = new ByteArrayInputStream(signData);
		ASN1Primitive derObj;
		try (ASN1InputStream dis = new ASN1InputStream(bis);) {
			derObj = dis.readObject();
		}
		Enumeration<ASN1Integer> e = ((ASN1Sequence) derObj).getObjects();
		BigInteger r = ((ASN1Integer) e.nextElement()).getValue();
		BigInteger s = ((ASN1Integer) e.nextElement()).getValue();
		SM2Result result = new SM2Result();
		result.r = r;
		result.s = s;

		sm2.sm2Verify(md, userKey, result.r, result.s, result);
		return result.r.equals(result.R);
	}

}
