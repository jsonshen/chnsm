package org.shenjia.chnsm;

import java.math.BigInteger;

class Codec {
	
	/**
	 * 整形转换成网络传输的字节流（字节数组）型数据
	 *
	 * @param num
	 *            一个整型数据
	 * @return 4个字节的自己数组
	 */
	static byte[] intToBytes(int num) {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) (0xff & (num >> 0));
		bytes[1] = (byte) (0xff & (num >> 8));
		bytes[2] = (byte) (0xff & (num >> 16));
		bytes[3] = (byte) (0xff & (num >> 24));
		return bytes;
	}

	/**
	 * 四个字节的字节数据转换成一个整形数据
	 *
	 * @param bytes
	 *            4个字节的字节数组
	 * @return 一个整型数据
	 */
	static int byteToInt(byte[] bytes) {
		int num = 0;
		int temp;
		temp = (0x000000ff & (bytes[0])) << 0;
		num = num | temp;
		temp = (0x000000ff & (bytes[1])) << 8;
		num = num | temp;
		temp = (0x000000ff & (bytes[2])) << 16;
		num = num | temp;
		temp = (0x000000ff & (bytes[3])) << 24;
		num = num | temp;
		return num;
	}

	/**
	 * 长整形转换成网络传输的字节流（字节数组）型数据
	 *
	 * @param num
	 *            一个长整型数据
	 * @return 4个字节的自己数组
	 */
	static byte[] longToBytes(long num) {
		byte[] bytes = new byte[8];
		for (int i = 0; i < 8; i++) {
			bytes[i] = (byte) (0xff & (num >> (i * 8)));
		}

		return bytes;
	}

	/**
	 * 大数字转换字节流（字节数组）型数据
	 *
	 * @param n
	 * @return
	 */
	static byte[] bigIntToBytes(BigInteger n) {
		byte tmpd[] = (byte[]) null;
		if (n == null) {
			return null;
		}

		if (n.toByteArray().length == 33) {
			tmpd = new byte[32];
			System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
		} else if (n.toByteArray().length == 32) {
			tmpd = n.toByteArray();
		} else {
			tmpd = new byte[32];
			for (int i = 0; i < 32 - n.toByteArray().length; i++) {
				tmpd[i] = 0;
			}
			System.arraycopy(n.toByteArray(), 0, tmpd, 32 - n.toByteArray().length, n.toByteArray().length);
		}
		return tmpd;
	}
}
