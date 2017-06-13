
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class MyFileEncryptor {
//	public static void main(String[] args) throws Exception {
//		String fileName = "C:\\Users\\Administrator\\workspace\\Test\\src\\MyFileEncryptor.java";
//		String encryptedFileName = "C:\\Users\\Administrator\\workspace\\Test\\src\\MyFileEncryptor.java.enc";
//		String password = "123456";
//		enryptFile(fileName, encryptedFileName, password);
//
//		String decryptedFileName = "C:\\Users\\Administrator\\workspace\\Test\\src\\MyFileEncryptor1.java";
//		decryptFile(encryptedFileName, decryptedFileName, password);
//
//	}

	public static void enryptFile(String fileName, String encryptedFileName, String password,int length) throws Exception {
		FileInputStream fis = new FileInputStream(fileName);
		FileOutputStream fos = new FileOutputStream(encryptedFileName);
		String keylength="SHA3-"+length*2;
		System.out.println(keylength);
		MessageDigest md = MessageDigest.getInstance(keylength);
		byte[] keyValue = md.digest(password.getBytes());
		System.out.println(keyValue.length*8);
		SecretKeySpec key = new SecretKeySpec(keyValue, 0, length/8, "AES");
		byte[] ivValue = new byte[16];
		Random random = new Random();
		random.nextBytes(ivValue);
		IvParameterSpec iv = new IvParameterSpec(ivValue);
		Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);

		CipherInputStream cis = new CipherInputStream(fis, cipher);
		fos.write("MyFileEncryptor".getBytes());
		fos.write(ivValue);

		byte[] buffer = new byte[64];
		int n = 0;
		while ((n = cis.read(buffer)) != -1) {
			fos.write(buffer, 0, n);
		}

		cis.close();
		fos.close();
	}

	public static void decryptFile(String encryptedFileName, String decryptedFileName, String password,int length)
			{
		try {
			FileInputStream fis = new FileInputStream(encryptedFileName);

			byte[] fileIdentifier = new byte[15];
			if (fis.read(fileIdentifier) == 15 && new String(fileIdentifier).equals("MyFileEncryptor")) {
				FileOutputStream fos = new FileOutputStream(decryptedFileName);

				String keylength="SHA3-"+length*2;
				System.out.println(keylength);
				MessageDigest md = MessageDigest.getInstance(keylength);
				byte[] keyValue = md.digest(password.getBytes());
				SecretKeySpec key = new SecretKeySpec(keyValue, 0, length/8, "AES");

				byte[] ivValue = new byte[16];
				fis.read(ivValue);
				IvParameterSpec iv = new IvParameterSpec(ivValue);

				Cipher cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, key, iv);

				CipherInputStream cis = new CipherInputStream(fis, cipher);

				byte[] buffer = new byte[64];
				int n = 0;
				while ((n = cis.read(buffer)) != -1) {
					fos.write(buffer, 0, n);
				}

				cis.close();
				fos.close();
				JOptionPane.showMessageDialog(null, "解密成功！");
			} else {
				JOptionPane.showMessageDialog(null, "文件格式错误！");
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(null, "密码错误！");
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(null, "解密长度选择错误或密码错误！");
			e.printStackTrace();
		}
	}
}
