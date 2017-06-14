
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.swing.JOptionPane;

public class TestFileSignature {
//	public static void main(String[] args) throws Exception {
//		String fileName = "aaaa.txt";
//		String signValueFile = fileName + ".sig";
//		signFile(fileName, signValueFile,"123456");
//		System.out.println(verifiFile(fileName, signValueFile,"123456"));
//	}
	
	
	//签名时从keystore文件中获取私钥，对文件签名；
	public static void signFile(String fileToSign,String signValueFile,String getpassword) throws Exception {
		// ()中创建的组员必须实现outcloseable接口
		
		TestGenerateCert.geterateKey(getpassword);
		
		try (FileInputStream fis = new FileInputStream(fileToSign);
				FileOutputStream fos = new FileOutputStream(signValueFile);
						FileInputStream in=new FileInputStream("mynewkeys.keystore")) {
			// 创建KeyStore对象，并从密钥库文件中读入内容
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			char[] password=getpassword.toCharArray();
			keyStore.load(in, password);
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
			KeyStore.PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("myrsakey", protParam);
			RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
			Signature signature = Signature.getInstance("SHA1withRSA");
			signature.initSign(privateKey);

			byte[] buffer = new byte[1024];
			int n = 0;
			while ((n = fis.read(buffer)) != -1) {
				signature.update(buffer, 0, n);
			}
			byte[] signValue = signature.sign();
			fos.write(signValue);
		}
	}
	
	//验证签名时从keystore文件中获取数字证书，从而获取公钥，然后验证签名。
	public static boolean verifiFile(String filetoVerify,String signValueFile,String vertifyKeystore,String getpassword) {
		{
			try {
				FileInputStream fis1=new FileInputStream(filetoVerify);
				FileInputStream fis2=new FileInputStream(signValueFile);
				// 创建KeyStore对象，并从密钥库文件中读入内容
				KeyStore keyStore = KeyStore.getInstance("JCEKS");
				FileInputStream fis = new FileInputStream(vertifyKeystore);
				char[] password=getpassword.toCharArray();
				keyStore.load(fis, password);
				// 把密钥库文件中内容加载到keystore对象中
				// 读取密钥对myrsakey中的公钥对应的自签名证书
				X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myrsakey");
				// 从数字证书中获取RSA公钥，并打印其内容（证书中只有公钥，没有私钥）
				RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
				Signature signature = Signature.getInstance("SHA1withRSA");
				signature.initVerify(rsaPublicKey);
				byte[] signValue = new byte[fis2.available()];
				fis2.read(signValue);
				byte[] buffer = new byte[1024];
				int n = 0;
				while ((n = fis1.read(buffer)) != -1) {
					signature.update(buffer, 0, n);
				}
				fis1.close();
				fis2.close();
				return signature.verify(signValue);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				JOptionPane.showMessageDialog(null, "找不到文件！");
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				JOptionPane.showMessageDialog(null, "验证失败,文件类型不符！");
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				JOptionPane.showMessageDialog(null, "验证失败（或密码错误）！");
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return false;
	}
}
