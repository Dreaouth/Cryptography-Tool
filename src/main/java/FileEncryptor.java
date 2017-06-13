

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
			//������Կ
			MessageDigest md=MessageDigest.getInstance("SHA1");
			byte[] hashValue=md.digest(password.getBytes());

			//������һ��������㣬�ڶ������ǳ���
			SecretKeySpec key=new SecretKeySpec(hashValue,0,16,"AES");
			//����IV
			byte[] ivValue=new byte[16];
			Random random=new Random(System.currentTimeMillis());
			random.nextBytes(ivValue);
			IvParameterSpec iv=new IvParameterSpec(ivValue);
			//д�����ļ�ͷ
			fos.write("FileEncryptor".getBytes());
			fos.write(ivValue);
			System.out.println(new HexBinaryAdapter().marshal(ivValue));
			//����������Cipher����
			Cipher cipher=Cipher.getInstance("AES/OFB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE,key,iv);
			//��ϢժҪ��������MessageInputStream)=�ļ�������(FileinputStream)+��ϢժҪ����(MessageDigest)
			//�ӽ�����������CipherInputStream��=�ļ���������FileInputStream��+Cipher
			
			//����������
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
				//������Կ
				MessageDigest md=MessageDigest.getInstance("SHA1");
				byte[] hashValue=md.digest(password.getBytes());
				SecretKeySpec key=new SecretKeySpec(hashValue,0,16,"AES");
				//�������ж�ȡiv
				byte[] ivValue=new byte[16];
				fis.read(ivValue);
				IvParameterSpec iv=new IvParameterSpec(ivValue);
				//����������Cipher�������ڼ���
				Cipher cipher=Cipher.getInstance("AES/OFB/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE,key,iv);
				//���ļ�������fis��װΪ�����ļ�������
				CipherInputStream cis=new CipherInputStream(fis, cipher);
				byte[] buffer=new byte[64];
				int n=0;
				while ((n=cis.read(buffer))!=-1) {
					fos.write(buffer,0,n);
				}
				cis.close();
				fos.close();
			}else {
				JOptionPane.showMessageDialog(null, "The file is not encrypted by me����");
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
