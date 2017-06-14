import java.io.FileInputStream;
import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.io.MacInputStream;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * MAC算法工具类
 * 对于HmacMD5、HmacSHA1、HmacSHA256、HmacSHA384、HmacSHA512应用的步骤都是一模一样的。具体看下面的代码
 */
public class MACCoder {

	/**
	 * HmacMd5摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD5(String data, String key) throws Exception {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacMD5");
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(signingKey);
        return new HexBinaryAdapter().marshal((mac.doFinal(data.getBytes())));
	}

	public static String encodeHmacMD5File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
        MD5Digest digest = new MD5Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacSHA1摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA(String data, String key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacSHAFile(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
        SHA1Digest digest = new SHA1Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacSHA256摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA256(String data, String key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacSHA256File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
        SHA256Digest digest = new SHA256Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}
	

	/**
	 * HmacSHA384摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA384(String data, String key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA384");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacSHA384File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
        SHA384Digest digest = new SHA384Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacSHA512摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA512(String data, String key) throws Exception {
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA512");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacSHA512File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
        SHA512Digest digest = new SHA512Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacMd2摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD2(String data, String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacMD2");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacMD2File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		MD2Digest digest = new MD2Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}


	/**
	 * HmacMD4摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacMD4(String data, String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacMD4");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacMD4File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		MD4Digest digest = new MD4Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacSHA224摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacSHA224(String data,String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA224");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacSHA224File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		SHA224Digest digest = new SHA224Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacRipeMD128摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacRipeMD128(String data, String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacRipeMD128");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacRipeMD128File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		RIPEMD128Digest digest = new RIPEMD128Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}

	/**
	 * HmacRipeMD160摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacRipeMD160(String data, String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "HmacRipeMD160");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacRipeMD160File(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		RIPEMD160Digest digest = new RIPEMD160Digest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}
	/**
	 * HmacRipeMD160摘要算法 对于给定生成的不同密钥，得到的摘要消息会不同，所以在实际应用中，要保存我们的密钥
	 */
	public static String encodeHmacTiger(String data, String key) throws Exception {
		// 添加BouncyCastle的支持
		Security.addProvider(new BouncyCastleProvider());
		// 还原密钥
		SecretKey secretKey = new SecretKeySpec(key.getBytes(), "Hmac-Tiger");
		// 实例化Mac
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		// 初始化mac
		mac.init(secretKey);
		// 执行消息摘要
		byte[] digest = mac.doFinal(data.getBytes());
		return new HexBinaryAdapter().marshal(digest);// 转为十六进制的字符串
	}
	public static String encodeHmacTigerFile(String filename,String key) throws Exception{
		FileInputStream fis=new FileInputStream(filename);
		TigerDigest digest = new TigerDigest();
        org.bouncycastle.crypto.Mac mac = new HMac(digest);
        KeyParameter parameter=new KeyParameter(key.getBytes());
        mac.init(parameter);
        MacInputStream in=new MacInputStream(fis, mac);
        byte[] buffer=new byte[4096];
        byte[] out=new byte[mac.getMacSize()];
        while(in.read(buffer)!=-1);
        mac.doFinal(out, 0);
        in.close();
        return new HexBinaryAdapter().marshal(out);
	}
}