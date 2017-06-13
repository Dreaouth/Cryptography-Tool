import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.util.encoders.Hex;

public class TestTime {
	public static long TestTimebyAES(String filename, String encryptedFileName,String length) throws Exception{
		long startTime=System.currentTimeMillis();
		FileInputStream fis=new FileInputStream(filename);
		FileOutputStream fos = new FileOutputStream(encryptedFileName);
		KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
		keyGenerator.init(Integer.parseInt(length));
		System.out.println(Integer.parseInt(length));
		Key key=keyGenerator.generateKey();
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
		long endTime=System.currentTimeMillis();
		return (endTime-startTime);
	}
	public static long TestTimebyHash(String filename,String Algorithms){
		long startTime=System.currentTimeMillis();
		try {
			MessageDigest md = MessageDigest.getInstance(Algorithms);
			FileInputStream in = new FileInputStream(filename);
			DigestInputStream dis=new DigestInputStream(in, md);
			byte[] buffer=new byte[4096];
			while (dis.read(buffer)!=-1);
			byte[] hashValue = md.digest();
			System.out.println(Hex.toHexString(hashValue));
			System.out.println(Algorithms);
			dis.close();
			in.close();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		long endTime=System.currentTimeMillis();
		return (endTime-startTime);
	}
}
