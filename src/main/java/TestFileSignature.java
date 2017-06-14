
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
	
	
	//ǩ��ʱ��keystore�ļ��л�ȡ˽Կ�����ļ�ǩ����
	public static void signFile(String fileToSign,String signValueFile,String getpassword) throws Exception {
		// ()�д�������Ա����ʵ��outcloseable�ӿ�
		
		TestGenerateCert.geterateKey(getpassword);
		
		try (FileInputStream fis = new FileInputStream(fileToSign);
				FileOutputStream fos = new FileOutputStream(signValueFile);
						FileInputStream in=new FileInputStream("mynewkeys.keystore")) {
			// ����KeyStore���󣬲�����Կ���ļ��ж�������
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
	
	//��֤ǩ��ʱ��keystore�ļ��л�ȡ����֤�飬�Ӷ���ȡ��Կ��Ȼ����֤ǩ����
	public static boolean verifiFile(String filetoVerify,String signValueFile,String vertifyKeystore,String getpassword) {
		{
			try {
				FileInputStream fis1=new FileInputStream(filetoVerify);
				FileInputStream fis2=new FileInputStream(signValueFile);
				// ����KeyStore���󣬲�����Կ���ļ��ж�������
				KeyStore keyStore = KeyStore.getInstance("JCEKS");
				FileInputStream fis = new FileInputStream(vertifyKeystore);
				char[] password=getpassword.toCharArray();
				keyStore.load(fis, password);
				// ����Կ���ļ������ݼ��ص�keystore������
				// ��ȡ��Կ��myrsakey�еĹ�Կ��Ӧ����ǩ��֤��
				X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myrsakey");
				// ������֤���л�ȡRSA��Կ������ӡ�����ݣ�֤����ֻ�й�Կ��û��˽Կ��
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
				JOptionPane.showMessageDialog(null, "�Ҳ����ļ���");
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				JOptionPane.showMessageDialog(null, "��֤ʧ��,�ļ����Ͳ�����");
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				JOptionPane.showMessageDialog(null, "��֤ʧ�ܣ���������󣩣�");
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return false;
	}
}
