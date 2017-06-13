
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Enumeration;

import javax.swing.JOptionPane;

public interface TestReadKeystore {
	public static void readkeys(String getpassword){
		try {
			// 创建KeyStore对象，并从密钥库文件中读入内容
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			char[] password = getpassword.toCharArray();
			FileInputStream fis = new FileInputStream("mynewkeys.keystore");
			//把密钥库文件中内容加载到keystore对象中
			keyStore.load(fis, password);
			// 遍历并打印密钥库中的所有别名
			Enumeration<String> alias = keyStore.aliases();
			System.out.println("密钥库中的所有条目别名如下：");
			Collections.list(alias).forEach(System.out::println);

			// 读取对称密钥myaeskey,创建一个对称密钥对象，并打印其内容
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
//		KeyStore.SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keyStore.getEntry("myaeskey", protParam);
//		SecretKey secretKey = secretKeyEntry.getSecretKey();
//		System.out.println("对称密钥算法名：" + secretKey.getAlgorithm());
//		System.out.println("对称密钥值：" + Hex.toHexString(secretKey.getEncoded()));

			// 读取密钥对myrsakey中的私钥，创建一个私钥对象，并打印其内容
			KeyStore.PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("myrsakey", protParam);
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
			System.out.println("RSA私钥参数 n = " + rsaPrivateKey.getModulus());
			System.out.println("RSA私钥参数 d = " + rsaPrivateKey.getPrivateExponent());

			// 读取密钥对myrsakey中的公钥对应的自签名证书，并打印其内容
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myrsakey");
			System.out.println("myrsakey中的公钥对应的自签名证书的内容如下：");
			System.out.println(certificate);
			// 从数字证书中获取RSA公钥，并打印其内容（证书中只有公钥，没有私钥）
			RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
			System.out.println("RSA公钥参数 n = " + rsaPublicKey.getModulus());
			System.out.println("RSA公钥参数 e = " + rsaPublicKey.getPublicExponent());
			fis.close();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(null, "密码错误！");
			e.printStackTrace();
		}
	}
	public static void main(String[] args){
		TestReadKeystore.readkeys("123456");
	}
}
