package org.shenjia.chnsm;

import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

public class SM3Cipher {
	
	private int ct;
	private ECPoint p2;
	private SM3Digest keyBase;
	private SM3Digest c3;
	private byte key[];
	private byte keyOff;

	public SM3Cipher() {
		this.ct = 1;
		this.key = new byte[32];
		this.keyOff = 0;
	}

	private void reset() {
		this.keyBase = new SM3Digest();
		this.c3 = new SM3Digest();

		byte p[] = Codec.bigIntToBytes(p2.normalize().getXCoord().toBigInteger());
		this.keyBase.update(p, 0, p.length);
		this.c3.update(p, 0, p.length);

		p = Codec.bigIntToBytes(p2.normalize().getYCoord().toBigInteger());
		this.keyBase.update(p, 0, p.length);
		this.ct = 1;
		nextKey();
	}

	private void nextKey() {
		SM3Digest sm3keycur = new SM3Digest(this.keyBase);
		sm3keycur.update((byte) (ct >> 24 & 0xff));
		sm3keycur.update((byte) (ct >> 16 & 0xff));
		sm3keycur.update((byte) (ct >> 8 & 0xff));
		sm3keycur.update((byte) (ct & 0xff));
		sm3keycur.doFinal(key, 0);
		this.keyOff = 0;
		this.ct++;
	}

	public ECPoint initEncrypt(SM2 sm2, ECPoint userKey) {
		AsymmetricCipherKeyPair key = sm2.ecKeyPairGen.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger k = ecpriv.getD();
		ECPoint c1 = ecpub.getQ();
		this.p2 = userKey.multiply(k);
		reset();
		return c1;
	}

	public void Encrypt(byte data[]) {
		this.c3.update(data, 0, data.length);
		for (int i = 0; i < data.length; i++) {
			if (keyOff == key.length) {
				nextKey();
			}
			data[i] ^= key[keyOff++];
		}
	}

	public void initDecrypt(BigInteger userD, ECPoint c1) {
		this.p2 = c1.multiply(userD);
		reset();
	}

	public void decrypt(byte data[]) {
		for (int i = 0; i < data.length; i++) {
			if (keyOff == key.length) {
				nextKey();
			}
			data[i] ^= key[keyOff++];
		}

		this.c3.update(data, 0, data.length);
	}

	public void dofinal(byte c3[]) {
		byte p[] = Codec.bigIntToBytes(p2.normalize().getYCoord().toBigInteger());
		this.c3.update(p, 0, p.length);
		this.c3.doFinal(c3, 0);
		reset();
	}
}
