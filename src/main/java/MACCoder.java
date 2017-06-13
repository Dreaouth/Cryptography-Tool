import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MAC�㷨������
 * ����HmacMD5��HmacSHA1��HmacSHA256��HmacSHA384��HmacSHA512Ӧ�õĲ��趼��һģһ���ġ����忴����Ĵ���
 */
public class MACCoder {
	/**
	 * ����HmacMD5ժҪ�㷨����Կ
	 */
	public static byte[] initHmacMD5Key() throws NoSuchAlgorithmException {
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD5");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMd5ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacMD5(byte[] data, byte[] key) throws Exception {
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacSHA1ժҪ�㷨����Կ
	 */
	public static byte[] initHmacSHAKey() throws NoSuchAlgorithmException {
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA1ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacSHA(byte[] data, byte[] key) throws Exception {
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA1");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacSHA256ժҪ�㷨����Կ
	 */
	public static byte[] initHmacSHA256Key() throws NoSuchAlgorithmException {
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA256ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacSHA256(byte[] data, byte[] key) throws Exception {
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacSHA256ժҪ�㷨����Կ
	 */
	public static byte[] initHmacSHA384Key() throws NoSuchAlgorithmException {
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA384");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA384ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacSHA384(byte[] data, byte[] key) throws Exception {
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA384");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacSHA256ժҪ�㷨����Կ
	 */
	public static byte[] initHmacSHA512Key() throws NoSuchAlgorithmException {
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA512");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA512ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacSHA512(byte[] data, byte[] key) throws Exception {
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA512");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacMD2ժҪ�㷨����Կ
	 */
	public static byte[] initHmacMD2Key() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD2");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMd2ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacMD2(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD2");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacMD4ժҪ�㷨����Կ
	 */
	public static byte[] initHmacMD4Key() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD4");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMD4ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacMD4(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD4");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacSHA224ժҪ�㷨����Կ
	 */
	public static byte[] initHmacSHA224Key() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA224");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA224ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacSHA224(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA224");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacRipeMD128ժҪ�㷨����Կ
	 */
	public static byte[] initHmacRipeMD128Key() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacRipeMD128");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD128ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacRipeMD128(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD128");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}

	/**
	 * ����HmacRipeMD160ժҪ�㷨����Կ
	 */
	public static byte[] initHmacRipeMD160Key() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("HmacRipeMD160");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD160ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacRipeMD160(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD160");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}


	/**
	 * ����HmacTigerժҪ�㷨����Կ
	 */
	public static byte[] initHmacTigerKey() throws NoSuchAlgorithmException {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		KeyGenerator generator = KeyGenerator.getInstance("Hmac-Tiger");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD160ժҪ�㷨 ���ڸ������ɵĲ�ͬ��Կ���õ���ժҪ��Ϣ�᲻ͬ��������ʵ��Ӧ���У�Ҫ�������ǵ���Կ
	 */
	public static String encodeHmacTiger(byte[] data, byte[] key) throws Exception {
		// ���BouncyCastle��֧��
		Security.addProvider(new BouncyCastleProvider());
		// ��ԭ��Կ
		SecretKey secretKey = new SecretKeySpec(key, "Hmac-Tiger");
		// ʵ����Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// תΪʮ�����Ƶ��ַ���
	}
}