package org.shenjia.chnsm;

public class SM4Context {
	
	public int mode;
	public long[] sk;

	public SM4Context() {
		this.mode = 1;
		this.sk = new long[32];
	}
}
