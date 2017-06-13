
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
			// ����KeyStore���󣬲�����Կ���ļ��ж�������
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			char[] password = getpassword.toCharArray();
			FileInputStream fis = new FileInputStream("mynewkeys.keystore");
			//����Կ���ļ������ݼ��ص�keystore������
			keyStore.load(fis, password);
			// ��������ӡ��Կ���е����б���
			Enumeration<String> alias = keyStore.aliases();
			System.out.println("��Կ���е�������Ŀ�������£�");
			Collections.list(alias).forEach(System.out::println);

			// ��ȡ�Գ���Կmyaeskey,����һ���Գ���Կ���󣬲���ӡ������
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
//		KeyStore.SecretKeyEntry secretKeyEntry = (SecretKeyEntry) keyStore.getEntry("myaeskey", protParam);
//		SecretKey secretKey = secretKeyEntry.getSecretKey();
//		System.out.println("�Գ���Կ�㷨����" + secretKey.getAlgorithm());
//		System.out.println("�Գ���Կֵ��" + Hex.toHexString(secretKey.getEncoded()));

			// ��ȡ��Կ��myrsakey�е�˽Կ������һ��˽Կ���󣬲���ӡ������
			KeyStore.PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("myrsakey", protParam);
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();
			System.out.println("RSA˽Կ���� n = " + rsaPrivateKey.getModulus());
			System.out.println("RSA˽Կ���� d = " + rsaPrivateKey.getPrivateExponent());

			// ��ȡ��Կ��myrsakey�еĹ�Կ��Ӧ����ǩ��֤�飬����ӡ������
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myrsakey");
			System.out.println("myrsakey�еĹ�Կ��Ӧ����ǩ��֤����������£�");
			System.out.println(certificate);
			// ������֤���л�ȡRSA��Կ������ӡ�����ݣ�֤����ֻ�й�Կ��û��˽Կ��
			RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
			System.out.println("RSA��Կ���� n = " + rsaPublicKey.getModulus());
			System.out.println("RSA��Կ���� e = " + rsaPublicKey.getPublicExponent());
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
			JOptionPane.showMessageDialog(null, "�������");
			e.printStackTrace();
		}
	}
	public static void main(String[] args){
		TestReadKeystore.readkeys("123456");
	}
}
