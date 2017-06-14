
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TestGenerateCert {
	// ������ǩ������֤��
	public static Certificate selfSign(KeyPair keyPair, String subjectDN, String signatureAlgorithm) throws Exception {
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		long now = System.currentTimeMillis();
		Date startDate = new Date(now);
		X500Name dnName = new X500Name(subjectDN);

		// Using the current time stamp as the certificate serial number
		BigInteger certSerialNumber = new BigInteger(Long.toString(now));

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity
		Date endDate = calendar.getTime();

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate,
				endDate, dnName, keyPair.getPublic());

		// Extensions --------------------------
		// Basic Constraints true for CA, false for EndEntity
		BasicConstraints basicConstraints = new BasicConstraints(true);
		// Basic Constraints is usually marked as critical.
		certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints);

		return new JcaX509CertificateConverter().setProvider(bcProvider)
				.getCertificate(certBuilder.build(contentSigner));
	}

	public static void geterateKey(String inputpassword) throws Exception{
		// ����RSA��Կ��
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		// ������ǩ������֤��
		String subjectDN = "CN = zhong OU = cauc O = cauc L = tj S = tj C = cn";
		String signatureAlgorithm = "SHA256WithRSA";
		Certificate certificate = selfSign(keyPair, subjectDN, signatureAlgorithm);
		System.out.println(certificate);

		// ����Կ�ԣ�˽Կ����ǩ������֤�飩������Կ���ļ�
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		char[] passWord = inputpassword.toCharArray();
		keyStore.load(null, passWord);
		keyStore.setKeyEntry("myrsakey", keyPair.getPrivate(),passWord, new Certificate[] { certificate });
		FileOutputStream fos = new FileOutputStream("mynewkeys.keystore");
		keyStore.store(fos, passWord);
	}
//	public static void main(String[] args) throws Exception {
//		TestGenerateCert.geterateKey("123456");
//	}
}

