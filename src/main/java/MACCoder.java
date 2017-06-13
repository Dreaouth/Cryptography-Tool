import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MAC算法工具类
 * 对于HmacMD5、HmacSHA1、HmacSHA256、HmacSHA384、HmacSHA512应用的步骤都是一模一样的。具体看下面的代码
 */
public class MACCoder {
	/**
	 * 产生HmacMD5摘要算法的密钥
	 */
	public static byte[] initHmacMD5Key() throws NoSuchAlgorithmException {
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD5");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMd5摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD5(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD5");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA1摘要算法的密钥
	 */
	public static byte[] initHmacSHAKey() throws NoSuchAlgorithmException {
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA1");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA1摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA1");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA256摘要算法的密钥
	 */
	public static byte[] initHmacSHA256Key() throws NoSuchAlgorithmException {
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA256摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA256(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA256");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA256摘要算法的密钥
	 */
	public static byte[] initHmacSHA384Key() throws NoSuchAlgorithmException {
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA384");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA384摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA384(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA384");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA256摘要算法的密钥
	 */
	public static byte[] initHmacSHA512Key() throws NoSuchAlgorithmException {
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA512");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA512摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA512(byte[] data, byte[] key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA512");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacMD2摘要算法的密钥
	 */
	public static byte[] initHmacMD2Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD2");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMd2摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD2(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD2");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacMD4摘要算法的密钥
	 */
	public static byte[] initHmacMD4Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacMD4");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacMD4摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD4(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacMD4");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacSHA224摘要算法的密钥
	 */
	public static byte[] initHmacSHA224Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacSHA224");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacSHA224摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA224(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacSHA224");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacRipeMD128摘要算法的密钥
	 */
	public static byte[] initHmacRipeMD128Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacRipeMD128");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD128摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacRipeMD128(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD128");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}

	/**
	 * 产生HmacRipeMD160摘要算法的密钥
	 */
	public static byte[] initHmacRipeMD160Key() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("HmacRipeMD160");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD160摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacRipeMD160(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "HmacRipeMD160");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}


	/**
	 * 产生HmacTiger摘要算法的密钥
	 */
	public static byte[] initHmacTigerKey() throws NoSuchAlgorithmException {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 初始化HmacMD5摘要算法的密钥产生器
		KeyGenerator generator = KeyGenerator.getInstance("Hmac-Tiger");
		// 产生密钥
		SecretKey secretKey = generator.generateKey();
		// 获得密钥
		byte[] key = secretKey.getEncoded();
		return key;
	}

	/**
	 * HmacRipeMD160摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacTiger(byte[] data, byte[] key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key, "Hmac-Tiger");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data);
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
}