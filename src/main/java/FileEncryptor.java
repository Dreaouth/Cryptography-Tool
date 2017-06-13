

import java.awt.HeadlessException;
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
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public class FileEncryptor {
	public static void encryptFile(String filename,String encrytedFileName,String password) {
		try {
			FileInputStream fis=new FileInputStream(filename);
			FileOutputStream fos=new FileOutputStream(encrytedFileName);
			//创建密钥
			MessageDigest md=MessageDigest.getInstance("SHA1");
			byte[] hashValue=md.digest(password.getBytes());

			//数组后第一个数是起点，第二个数是长度
			SecretKeySpec key=new SecretKeySpec(hashValue,0,16,"AES");
			//创建IV
			byte[] ivValue=new byte[16];
			Random random=new Random(System.currentTimeMillis());
			random.nextBytes(ivValue);
			IvParameterSpec iv=new IvParameterSpec(ivValue);
			//写密文文件头
			fos.write("FileEncryptor".getBytes());
			fos.write(ivValue);
			System.out.println(new HexBinaryAdapter().marshal(ivValue));
			//创建并配置Cipher对象
			Cipher cipher=Cipher.getInstance("AES/OFB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE,key,iv);
			//消息摘要输入流（MessageInputStream)=文件输入流(FileinputStream)+消息摘要对象(MessageDigest)
			//加解密输入流（CipherInputStream）=文件输入流（FileInputStream）+Cipher
			
			//创建输入流
			CipherInputStream cis=new CipherInputStream(fis, cipher);
			byte[] buffer=new byte[64];
			int n=0;
			while ((n=cis.read(buffer))!=-1) {
				fos.write(buffer,0,n);
			}
			cis.close();
			fos.close();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
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
			e.printStackTrace();
		}
	}
	public static void decryptFile(String encryptedFileName,String decryptedFileName,String password) {
		try {
			FileInputStream fis=new FileInputStream(encryptedFileName);
			FileOutputStream fos=new FileOutputStream(decryptedFileName);
			byte[] fileIdentifier=new byte[13];
			fis.read(fileIdentifier);
			if (new String(fileIdentifier).equals("FileEncryptor")) {
				//创建密钥
				MessageDigest md=MessageDigest.getInstance("SHA1");
				byte[] hashValue=md.digest(password.getBytes());
				SecretKeySpec key=new SecretKeySpec(hashValue,0,16,"AES");
				//从密文中读取iv
				byte[] ivValue=new byte[16];
				fis.read(ivValue);
				IvParameterSpec iv=new IvParameterSpec(ivValue);
				//创建并配置Cipher对象用于加密
				Cipher cipher=Cipher.getInstance("AES/OFB/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE,key,iv);
				//将文件输入流fis封装为解密文件输入流
				CipherInputStream cis=new CipherInputStream(fis, cipher);
				byte[] buffer=new byte[64];
				int n=0;
				while ((n=cis.read(buffer))!=-1) {
					fos.write(buffer,0,n);
				}
				cis.close();
				fos.close();
			}else {
				JOptionPane.showMessageDialog(null, "The file is not encrypted by me！！");
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (HeadlessException e) {
			// TODO Auto-generated catch block
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
			e.printStackTrace();
		}
	}
}
