
import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.SoftBevelBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class Cryptography_Tool extends JFrame {
	String s = "×Ö·û´®";
	String MACs = "×Ö·û´®";
	private JPanel contentPane;
	private static final long serialVersionUID = 1L;
	private JTextField textField_message;
	private JTextField textField_MD5;
	private JTextField textField_SHA1;
	private JTextField textField_SHA_224;
	private JTextField textField_SHA_256;
	private JTextField textField_SHA_384;
	private JTextField textField_SHA_512;
	private JTextField textField_SHA3_224;
	private JTextField textField_SHA3_256;
	private JTextField textField_SHA3_384;
	private JTextField textField_SHA3_512;
	private JCheckBox chckbx_MD5;
	private JCheckBox chckbx_SHA1;
	private JCheckBox chckbx_SHA_224;
	private JCheckBox chckbx_SHA_256;
	private JCheckBox chckbx_SHA_384;
	private JCheckBox chckbx_SHA_512;
	private JCheckBox chckbx_SHA3_224;
	private JCheckBox chckbx_SHA3_256;
	private JCheckBox chckbx_SHA3_384;
	private JCheckBox chckbx_SHA3_512;
	private JPanel panel;
	private JTextField textField;
	private JTextField textField_choosefile_encry;
	private JButton btn_choosefile_encry;
	private JButton button_encrypt;
	private JTextField textField_choosefile_decrypt;
	private JButton button_choosefile_decrypt;
	private JRadioButton rdbtn_encrypt128;
	private JRadioButton rdbtn_encrypt192;
	private JRadioButton rdbtn_encrypt256;
	private JLabel label_3;
	String items[] = { "×Ö·û´®", "ÎÄ¼þ" };
	private JButton btn_choosefileHash;
	private JPasswordField passwordField_encrypt1;
	private JPasswordField passwordField_encrypt2;
	private JPasswordField passwordField_decrypt;
	private JTextField textField_sign;
	private JTextField textField_select_verify;
	private JTextField textField_Select_signValue;
	private JPasswordField passwordField_passwordsign;
	private JPasswordField passwordField_passwordsign2;
	private JLabel label_11;
	private JTextField textField_inputorSelectMAC;
	private JCheckBox chckbx_HmacMD5;
	private JCheckBox chckbx_HmacSHA1;
	private JCheckBox chckbx_HmacSHA256;
	private JCheckBox chckbx_HmacSHA384;
	private JCheckBox chckbx_HmacSHA512;
	private JCheckBox chckbx_HmacMD2;
	private JCheckBox chckbx_HmacMD4;
	private JCheckBox chckbx_HmacRipeMD128;
	private JCheckBox chckbx_HmacRipeMD160;
	private JCheckBox chckbx_HmacSHA224;
	private JCheckBox chckbx_HmacTiger;
	private JTextField textField_HmacMD5;
	private JTextField textField_HmacSHA1;
	private JTextField textField_HmacSHA256;
	private JTextField textField_HmacSHA384;
	private JTextField textField_HmacSHA512;
	private JTextField textField_HmacMD2;
	private JTextField textField_HmacMD4;
	private JTextField textField_HmacRipeMD128;
	private JTextField textField_HmacRipeMD160;
	private JTextField textField_HmacSHA224;
	private JButton button_MACclac;
	private JButton button_MACclear;
	private JTextField textField_HmacTiger;
	private JTabbedPane tabbedPane_1;
	private JPanel panel_AES;
	private JPanel panel_2;
	private JTextField textField_AES10M;
	private JTextField textField_AES100M;
	private JTextField textField_AES500M;
	private JTextField textField_AES1G;
	private JTextField textField_AEStime10M;
	private JTextField textField_AEStime100M;
	private JTextField textField_AEStime500M;
	private JTextField textField_AEStime1G;
	private JLabel label_12;
	private JButton btn_TestAES;
	private JLabel label_13;
	private JRadioButton rdbtn_SHA1;
	private JRadioButton rdbtn_SHA256;
	private JRadioButton rdbtn_SHA384;
	private JRadioButton rdbtn_SHA512;
	private JLabel label_14;
	private JLabel lblm_3;
	private JTextField textField_HASH10M;
	private JTextField textField_HASH100M;
	private JLabel lblm_4;
	private JTextField textField_HASH500M;
	private JLabel lblg_1;
	private JTextField textField_HASH1G;
	private JButton btn_selectHash10M;
	private JButton btn_selectHash100M;
	private JButton btn_selectHash500M;
	private JButton btn_selectHash1G;
	private JTextField textField_timeHash10M;
	private JTextField textField_timeHash100M;
	private JTextField textField_timeHash500M;
	private JTextField textField_timeHash1G;
	private JLabel label_18;
	private JButton btn_TestHash;
	private JTextField textField_MACkey;
	private JTextField textField_Select_vertify_keystore;
	private JLabel label_10;
	private JPasswordField passwordField_keystore;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Cryptography_Tool frame = new Cryptography_Tool();
					frame.setResizable(false);
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public Cryptography_Tool() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 571, 702);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		contentPane.setLayout(new BorderLayout(0, 0));
		setContentPane(contentPane);

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		contentPane.add(tabbedPane, BorderLayout.CENTER);

		JPanel panel_hash = new JPanel();
		tabbedPane.addTab("HASHÖµ¼ÆËã", null, panel_hash, null);
		panel_hash.setLayout(null);

		textField_message = new JTextField();
		textField_message.setBounds(116, 43, 367, 24);
		panel_hash.add(textField_message);
		textField_message.setColumns(10);

		textField_MD5 = new JTextField();
		textField_MD5.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_MD5.setEditable(false);
		textField_MD5.setBounds(116, 139, 367, 24);
		panel_hash.add(textField_MD5);
		textField_MD5.setColumns(10);
		JButton btn_calc = new JButton("\u8BA1\u7B97");
		btn_calc.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				MessageDigest md;
				textField_MD5.setText(null);
				textField_SHA1.setText(null);
				textField_SHA3_224.setText(null);
				textField_SHA3_256.setText(null);
				textField_SHA3_384.setText(null);
				textField_SHA3_512.setText(null);
				textField_SHA_224.setText(null);
				textField_SHA_256.setText(null);
				textField_SHA_384.setText(null);
				textField_SHA_512.setText(null);
				try {
					byte msg[] = textField_message.getText().getBytes();
					if (chckbx_MD5.isSelected()) {	
						md = MessageDigest.getInstance("MD5");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_MD5.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA1.isSelected()) {
						md = MessageDigest.getInstance("SHA1");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA1.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_224.isSelected()) {
						md = MessageDigest.getInstance("SHA-224");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA_224.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_256.isSelected()) {
						md = MessageDigest.getInstance("SHA-256");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA_256.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_384.isSelected()) {
						md = MessageDigest.getInstance("SHA-384");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA_384.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_512.isSelected()) {
						md = MessageDigest.getInstance("SHA-512");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA_512.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_224.isSelected()) {
						md = MessageDigest.getInstance("SHA3-224");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA3_224.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_256.isSelected()) {
						md = MessageDigest.getInstance("SHA3-256");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA3_256.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_384.isSelected()) {
						md = MessageDigest.getInstance("SHA3-384");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA3_384.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_512.isSelected()) {
						md = MessageDigest.getInstance("SHA3-512");
						if (s.equals("ÎÄ¼þ")) {
							FileInputStream in = new FileInputStream(textField_message.getText());
							DigestInputStream dis=new DigestInputStream(in, md);
							byte[] buffer=new byte[4096];
							while (dis.read(buffer)!=-1);   //¿¼ÊÔÉ¾µôÖØÐ´
							dis.close();
							in.close();
						}
						else {
							md.update(msg);
						}
						byte[] hashValue = md.digest();
						textField_SHA3_512.setText(Hex.toHexString(hashValue).toUpperCase());
					}
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (FileNotFoundException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		btn_calc.setBounds(38, 553, 113, 27);
		panel_hash.add(btn_calc);

		JButton btn_clear = new JButton("\u6E05\u7A7A");
		btn_clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				textField_message.setText(null);
				textField_MD5.setText(null);
				textField_SHA1.setText(null);
				textField_SHA3_224.setText(null);
				textField_SHA3_256.setText(null);
				textField_SHA3_384.setText(null);
				textField_SHA3_512.setText(null);
				textField_SHA_224.setText(null);
				textField_SHA_256.setText(null);
				textField_SHA_384.setText(null);
				textField_SHA_512.setText(null);
				chckbx_MD5.setSelected(false);
				chckbx_SHA1.setSelected(false);
				chckbx_SHA_224.setSelected(false);
				chckbx_SHA_256.setSelected(false);
				chckbx_SHA_384.setSelected(false);
				chckbx_SHA_512.setSelected(false);
				chckbx_SHA3_224.setSelected(false);
				chckbx_SHA3_256.setSelected(false);
				chckbx_SHA3_384.setSelected(false);
				chckbx_SHA3_512.setSelected(false);
			}
		});
		btn_clear.setBounds(209, 553, 113, 27);
		panel_hash.add(btn_clear);

		JButton btn_close = new JButton("\u5173\u95ED");
		btn_close.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		btn_close.setBounds(381, 553, 113, 27);
		panel_hash.add(btn_close);

		textField_SHA1 = new JTextField();
		textField_SHA1.setEditable(false);
		textField_SHA1.setColumns(10);
		textField_SHA1.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA1.setBounds(116, 184, 367, 24);
		panel_hash.add(textField_SHA1);

		textField_SHA_224 = new JTextField();
		textField_SHA_224.setEditable(false);
		textField_SHA_224.setColumns(10);
		textField_SHA_224.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA_224.setBounds(116, 225, 367, 24);
		panel_hash.add(textField_SHA_224);

		textField_SHA_256 = new JTextField();
		textField_SHA_256.setEditable(false);
		textField_SHA_256.setColumns(10);
		textField_SHA_256.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA_256.setBounds(116, 261, 367, 24);
		panel_hash.add(textField_SHA_256);

		textField_SHA_384 = new JTextField();
		textField_SHA_384.setEditable(false);
		textField_SHA_384.setColumns(10);
		textField_SHA_384.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA_384.setBounds(116, 302, 367, 24);
		panel_hash.add(textField_SHA_384);

		textField_SHA_512 = new JTextField();
		textField_SHA_512.setEditable(false);
		textField_SHA_512.setColumns(10);
		textField_SHA_512.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA_512.setBounds(116, 339, 367, 24);
		panel_hash.add(textField_SHA_512);

		textField_SHA3_224 = new JTextField();
		textField_SHA3_224.setEditable(false);
		textField_SHA3_224.setColumns(10);
		textField_SHA3_224.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA3_224.setBounds(116, 380, 367, 24);
		panel_hash.add(textField_SHA3_224);

		textField_SHA3_256 = new JTextField();
		textField_SHA3_256.setEditable(false);
		textField_SHA3_256.setColumns(10);
		textField_SHA3_256.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA3_256.setBounds(116, 416, 367, 24);
		panel_hash.add(textField_SHA3_256);

		textField_SHA3_384 = new JTextField();
		textField_SHA3_384.setEditable(false);
		textField_SHA3_384.setColumns(10);
		textField_SHA3_384.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA3_384.setBounds(116, 453, 367, 24);
		panel_hash.add(textField_SHA3_384);

		textField_SHA3_512 = new JTextField();
		textField_SHA3_512.setEditable(false);
		textField_SHA3_512.setColumns(10);
		textField_SHA3_512.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_SHA3_512.setBounds(116, 490, 367, 24);
		panel_hash.add(textField_SHA3_512);

		chckbx_MD5 = new JCheckBox("MD5");
		chckbx_MD5.setBounds(18, 138, 72, 27);
		panel_hash.add(chckbx_MD5);

		chckbx_SHA1 = new JCheckBox("SHA1");
		chckbx_SHA1.setBounds(18, 183, 93, 27);
		panel_hash.add(chckbx_SHA1);

		chckbx_SHA_224 = new JCheckBox("SHA-224");
		chckbx_SHA_224.setBounds(18, 224, 93, 27);
		panel_hash.add(chckbx_SHA_224);

		chckbx_SHA_256 = new JCheckBox("SHA-256");
		chckbx_SHA_256.setBounds(18, 260, 93, 27);
		panel_hash.add(chckbx_SHA_256);

		chckbx_SHA_384 = new JCheckBox("SHA-384");
		chckbx_SHA_384.setBounds(18, 301, 93, 27);
		panel_hash.add(chckbx_SHA_384);

		chckbx_SHA_512 = new JCheckBox("SHA-512");
		chckbx_SHA_512.setBounds(18, 338, 93, 27);
		panel_hash.add(chckbx_SHA_512);

		chckbx_SHA3_224 = new JCheckBox("SHA3-224");
		chckbx_SHA3_224.setBounds(18, 379, 93, 27);
		panel_hash.add(chckbx_SHA3_224);

		chckbx_SHA3_256 = new JCheckBox("SHA3-256");
		chckbx_SHA3_256.setBounds(18, 413, 93, 27);
		panel_hash.add(chckbx_SHA3_256);

		chckbx_SHA3_384 = new JCheckBox("SHA3-384");
		chckbx_SHA3_384.setBounds(18, 452, 93, 27);
		panel_hash.add(chckbx_SHA3_384);

		chckbx_SHA3_512 = new JCheckBox("SHA3-512");
		chckbx_SHA3_512.setBounds(18, 486, 93, 27);
		panel_hash.add(chckbx_SHA3_512);

		JComboBox comboBox = new JComboBox(items);
		comboBox.setBounds(18, 43, 72, 24);
		panel_hash.add(comboBox);
		comboBox.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				// TODO Auto-generated method stub
				if (e.getStateChange() == ItemEvent.SELECTED) {
					s = (String) comboBox.getSelectedItem();
					textField_message.setText(null);
					if (s.equals("×Ö·û´®")) {
						btn_choosefileHash.setVisible(false);
						textField_message.setEditable(true);
					}
					if (s.equals("ÎÄ¼þ")) {
						btn_choosefileHash.setVisible(true);
						textField_message.setEditable(false);
					}
				}
			}
		});

		btn_choosefileHash = new JButton("...");
		btn_choosefileHash.setVisible(false);
		btn_choosefileHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_message.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_choosefileHash.setBounds(497, 42, 27, 27);
		panel_hash.add(btn_choosefileHash);

		JPanel panel_fileDE = new JPanel();
		tabbedPane.addTab("ÎÄ¼þ¼Ó½âÃÜ", null, panel_fileDE, null);
		panel_fileDE.setLayout(null);

		JLabel encry = new JLabel("\u6587\u4EF6\u52A0\u5BC6:");
		encry.setFont(new Font("Î¢ÈíÑÅºÚ", Font.BOLD, 18));
		encry.setBounds(14, 13, 99, 26);
		panel_fileDE.add(encry);

		JLabel decry = new JLabel("\u6587\u4EF6\u89E3\u5BC6:");
		decry.setFont(new Font("Î¢ÈíÑÅºÚ", Font.BOLD, 18));
		decry.setBounds(14, 335, 99, 26);
		panel_fileDE.add(decry);

		JLabel password1 = new JLabel("\u5BC6\u7801:");
		password1.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		password1.setBounds(14, 162, 80, 26);
		panel_fileDE.add(password1);

		JLabel password2 = new JLabel("\u786E\u8BA4\u5BC6\u7801:");
		password2.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		password2.setBounds(14, 201, 80, 26);
		panel_fileDE.add(password2);

		textField_choosefile_encry = new JTextField();
		textField_choosefile_encry.setEditable(false);
		textField_choosefile_encry.setBounds(14, 52, 467, 26);
		panel_fileDE.add(textField_choosefile_encry);
		textField_choosefile_encry.setColumns(10);

		btn_choosefile_encry = new JButton("...");
		btn_choosefile_encry.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_choosefile_encry.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_choosefile_encry.setBounds(495, 52, 29, 26);
		panel_fileDE.add(btn_choosefile_encry);

		button_encrypt = new JButton("\u52A0\u5BC6");
		button_encrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String encryfilename = textField_choosefile_encry.getText();
				String encryptfilename = encryfilename + ".enc";
				char[] password1 = passwordField_encrypt1.getPassword();
				char[] password2 = passwordField_encrypt2.getPassword();
				int encrypt_length = 0;
				if (rdbtn_encrypt128.isSelected()) {
					encrypt_length = Integer.parseInt(rdbtn_encrypt128.getText());
				}
				if (rdbtn_encrypt192.isSelected()) {
					encrypt_length = Integer.parseInt(rdbtn_encrypt192.getText());
				}
				if (rdbtn_encrypt256.isSelected()) {
					encrypt_length = Integer.parseInt(rdbtn_encrypt256.getText());
				}
				if (Arrays.equals(password1, password2)) {
					String password = new String(password1);
					if (password.equals("")) {
						JOptionPane.showMessageDialog(null, "ÃÜÂë²»ÄÜÎª¿Õ£¡");
					}
					try {
						MyFileEncryptor.enryptFile(encryfilename, encryptfilename, password, encrypt_length);
						JOptionPane.showMessageDialog(null, "¼ÓÃÜ³É¹¦£¡");
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					JOptionPane.showMessageDialog(null, "Á½´ÎÊäÈë¿ÚÁî²»Ò»ÖÂ£¬ÇëÖØÐÂÊäÈë£¡");
					passwordField_encrypt1.setText("");
					passwordField_encrypt2.setText("");
				}
			}
		});
		button_encrypt.setBounds(198, 289, 80, 27);
		panel_fileDE.add(button_encrypt);

		textField_choosefile_decrypt = new JTextField();
		textField_choosefile_decrypt.setEditable(false);
		textField_choosefile_decrypt.setColumns(10);
		textField_choosefile_decrypt.setBounds(14, 374, 467, 26);
		panel_fileDE.add(textField_choosefile_decrypt);

		button_choosefile_decrypt = new JButton("...");
		button_choosefile_decrypt.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_choosefile_decrypt.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		button_choosefile_decrypt.setBounds(495, 374, 29, 26);
		panel_fileDE.add(button_choosefile_decrypt);

		JLabel label = new JLabel("\u5BC6\u7801:");
		label.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label.setBounds(14, 439, 80, 26);
		panel_fileDE.add(label);

		JButton button_decry = new JButton("\u89E3\u5BC6");
		button_decry.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String decryfilename = textField_choosefile_decrypt.getText();
				String after_decryfilename = textField_choosefile_decrypt.getText() + ".txt";
				char[] password_char = passwordField_decrypt.getPassword();
				String password = new String(password_char);
				try {
					MyFileEncryptor.decryptFile(decryfilename, after_decryfilename, password);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		button_decry.setBounds(198, 527, 80, 27);
		panel_fileDE.add(button_decry);

		JLabel label_1 = new JLabel("\u8BF7\u9009\u62E9\u52A0\u5BC6\u957F\u5EA6:");
		label_1.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_1.setBounds(14, 91, 217, 26);
		panel_fileDE.add(label_1);

		rdbtn_encrypt128 = new JRadioButton("128");
		rdbtn_encrypt128.setBounds(10, 126, 89, 27);
		panel_fileDE.add(rdbtn_encrypt128);
		rdbtn_encrypt128.setSelected(true);
		rdbtn_encrypt192 = new JRadioButton("192");
		rdbtn_encrypt192.setBounds(105, 126, 89, 27);
		panel_fileDE.add(rdbtn_encrypt192);

		rdbtn_encrypt256 = new JRadioButton("256");
		rdbtn_encrypt256.setBounds(222, 126, 89, 27);
		panel_fileDE.add(rdbtn_encrypt256);
		ButtonGroup group = new ButtonGroup();
		group.add(rdbtn_encrypt128);
		group.add(rdbtn_encrypt192);
		group.add(rdbtn_encrypt256);

		ButtonGroup buttonGroup = new ButtonGroup();
		label_3 = new JLabel("\uFF08\u8BF7\u8F93\u5165\u957F\u5EA6\u4E3A6-16\u4F4D\u7684\u5BC6\u7801\uFF09");
		label_3.setFont(new Font("ËÎÌå", Font.PLAIN, 15));
		label_3.setBounds(246, 232, 217, 26);
		panel_fileDE.add(label_3);

		passwordField_encrypt1 = new JPasswordField();
		passwordField_encrypt1.setBounds(108, 163, 288, 24);
		panel_fileDE.add(passwordField_encrypt1);

		passwordField_encrypt2 = new JPasswordField();
		passwordField_encrypt2.setBounds(108, 202, 288, 24);
		panel_fileDE.add(passwordField_encrypt2);

		passwordField_decrypt = new JPasswordField();
		passwordField_decrypt.setBounds(108, 441, 288, 24);
		panel_fileDE.add(passwordField_decrypt);

		JPanel panel_fileSign = new JPanel();
		tabbedPane.addTab("ÎÄ¼þÇ©Ãû", null, panel_fileSign, null);
		panel_fileSign.setLayout(null);

		JLabel sign = new JLabel("\u6587\u4EF6\u7B7E\u540D:");
		sign.setFont(new Font("Î¢ÈíÑÅºÚ", Font.BOLD, 18));
		sign.setBounds(19, 18, 99, 26);
		panel_fileSign.add(sign);

		textField_sign = new JTextField();
		textField_sign.setEditable(false);
		textField_sign.setBounds(29, 57, 427, 24);
		panel_fileSign.add(textField_sign);
		textField_sign.setColumns(10);

		JButton btn_select_sign = new JButton("...");
		btn_select_sign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_sign.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_select_sign.setBounds(470, 56, 25, 27);
		panel_fileSign.add(btn_select_sign);

		JLabel label_4 = new JLabel("\u8F93\u5165\u5BC6\u7801:");
		label_4.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_4.setBounds(19, 119, 77, 26);
		panel_fileSign.add(label_4);

		JButton button_sign = new JButton("\u6267\u884C\u7B7E\u540D");
		button_sign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String signFile = textField_sign.getText();
				char[] password1 = passwordField_passwordsign.getPassword();
				char[] password2 = passwordField_passwordsign2.getPassword();
				if (Arrays.equals(password1, password2)) {
					String password = new String(password1);
					if (password.equals("")) {
						JOptionPane.showMessageDialog(null, "ÃÜÂë²»ÄÜÎª¿Õ£¡");
					}
					try {
						TestGenerateCert.geterateKey(password);
						TestFileSignature.signFile(signFile, signFile + ".sig", password);
						JOptionPane.showMessageDialog(null, "Ç©Ãû³É¹¦£¡");
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					JOptionPane.showMessageDialog(null, "Á½´ÎÊäÈë¿ÚÁî²»Ò»ÖÂ£¬ÇëÖØÐÂÊäÈë£¡");
					passwordField_encrypt1.setText("");
					passwordField_encrypt2.setText("");
				}
			}
		});
		button_sign.setBounds(177, 245, 113, 27);
		panel_fileSign.add(button_sign);

		JLabel label_5 = new JLabel("\u7B7E\u540D\u9A8C\u8BC1:");
		label_5.setFont(new Font("Î¢ÈíÑÅºÚ", Font.BOLD, 18));
		label_5.setBounds(19, 286, 99, 26);
		panel_fileSign.add(label_5);

		JLabel label_6 = new JLabel("\u786E\u8BA4\u5BC6\u7801:");
		label_6.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_6.setBounds(19, 174, 77, 26);
		panel_fileSign.add(label_6);

		textField_select_verify = new JTextField();
		textField_select_verify.setEditable(false);
		textField_select_verify.setColumns(10);
		textField_select_verify.setBounds(29, 331, 427, 24);
		panel_fileSign.add(textField_select_verify);

		JLabel label_7 = new JLabel("\uFF08\u9009\u62E9\u8981\u8FDB\u884C\u7B7E\u540D\u7684\u6587\u4EF6\uFF09");
		label_7.setFont(new Font("ËÎÌå", Font.PLAIN, 13));
		label_7.setBounds(309, 80, 215, 26);
		panel_fileSign.add(label_7);

		JLabel label_8 = new JLabel("\uFF08\u9009\u62E9\u8981\u9A8C\u8BC1\u7B7E\u540D\u7684\u6587\u4EF6\uFF09");
		label_8.setFont(new Font("ËÎÌå", Font.PLAIN, 13));
		label_8.setBounds(309, 357, 215, 26);
		panel_fileSign.add(label_8);

		textField_Select_signValue = new JTextField();
		textField_Select_signValue.setEditable(false);
		textField_Select_signValue.setColumns(10);
		textField_Select_signValue.setBounds(29, 383, 427, 24);
		panel_fileSign.add(textField_Select_signValue);

		JLabel label_9 = new JLabel("\uFF08\u9009\u62E9\u50A8\u5B58\u7B7E\u540D\u503C\u7684\u6587\u4EF6\uFF09");
		label_9.setFont(new Font("ËÎÌå", Font.PLAIN, 13));
		label_9.setBounds(309, 409, 215, 26);
		panel_fileSign.add(label_9);

		JButton button_select_verify1 = new JButton("...");
		button_select_verify1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_select_verify.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		button_select_verify1.setBounds(470, 330, 25, 27);
		panel_fileSign.add(button_select_verify1);

		JButton button_select_verify2 = new JButton("...");
		button_select_verify2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_Select_signValue.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		button_select_verify2.setBounds(470, 382, 25, 27);
		panel_fileSign.add(button_select_verify2);

		JButton button_verify = new JButton("\u7B7E\u540D\u9A8C\u8BC1");
		button_verify.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String vertifyFile = textField_select_verify.getText();
				String signValueFile = textField_Select_signValue.getText();
				String vertifyKeystore=textField_Select_vertify_keystore.getText();
				String password=new String(passwordField_keystore.getPassword());
				try {
					boolean judge = TestFileSignature.verifiFile(vertifyFile, signValueFile,vertifyKeystore,password);
					if (judge) {
						JOptionPane.showMessageDialog(null, "ÑéÖ¤³É¹¦£¡");
					}
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		button_verify.setBounds(177, 553, 113, 27);
		panel_fileSign.add(button_verify);

		passwordField_passwordsign = new JPasswordField();
		passwordField_passwordsign.setBounds(122, 120, 322, 24);
		panel_fileSign.add(passwordField_passwordsign);

		passwordField_passwordsign2 = new JPasswordField();
		passwordField_passwordsign2.setBounds(122, 175, 322, 24);
		panel_fileSign.add(passwordField_passwordsign2);

		label_11 = new JLabel("\uFF08\u8BF7\u8F93\u5165\u957F\u5EA6\u4E3A6-16\u4F4D\u7684\u5BC6\u7801\uFF09");
		label_11.setFont(new Font("ËÎÌå", Font.PLAIN, 13));
		label_11.setBounds(309, 204, 217, 26);
		panel_fileSign.add(label_11);
		
		textField_Select_vertify_keystore = new JTextField();
		textField_Select_vertify_keystore.setEditable(false);
		textField_Select_vertify_keystore.setColumns(10);
		textField_Select_vertify_keystore.setBounds(31, 437, 427, 24);
		panel_fileSign.add(textField_Select_vertify_keystore);
		
		label_10 = new JLabel("\uFF08\u9009\u62E9\u5BC6\u94A5\u5E93\u6587\u4EF6\uFF09");
		label_10.setFont(new Font("ËÎÌå", Font.PLAIN, 13));
		label_10.setBounds(309, 463, 215, 26);
		panel_fileSign.add(label_10);
		
		JButton button_selectVerify_keystore = new JButton("...");
		button_selectVerify_keystore.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("C:/Users/liu/workspace/ÃÜÂëÑ§×ÛºÏ¹¤¾ß");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_Select_vertify_keystore.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		button_selectVerify_keystore.setBounds(473, 435, 25, 27);
		panel_fileSign.add(button_selectVerify_keystore);
		
		passwordField_keystore = new JPasswordField();
		passwordField_keystore.setBounds(122, 491, 322, 24);
		panel_fileSign.add(passwordField_keystore);
		
		JLabel label_15 = new JLabel("\u5BC6\u94A5\u5E93\u53E3\u4EE4:");
		label_15.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_15.setBounds(19, 494, 99, 18);
		panel_fileSign.add(label_15);

		JPanel panel_MAC = new JPanel();
		tabbedPane.addTab("ÏûÏ¢ÈÏÖ¤Âë", null, panel_MAC, null);
		panel_MAC.setLayout(null);
		JComboBox comboBoxMAC = new JComboBox(items);
		comboBoxMAC.setBounds(40, 43, 72, 24);
		panel_MAC.add(comboBoxMAC);

		textField_inputorSelectMAC = new JTextField();
		textField_inputorSelectMAC.setBounds(150, 43, 330, 24);
		panel_MAC.add(textField_inputorSelectMAC);
		textField_inputorSelectMAC.setColumns(10);

		JButton btn_selectMAC = new JButton("...");
		btn_selectMAC.setVisible(false);
		btn_selectMAC.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_inputorSelectMAC.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectMAC.setBounds(494, 42, 22, 27);
		panel_MAC.add(btn_selectMAC);
		comboBoxMAC.addItemListener(new ItemListener() {

			@Override
			public void itemStateChanged(ItemEvent e) {
				// TODO Auto-generated method stub
				if (e.getStateChange() == ItemEvent.SELECTED) {
					MACs = (String) comboBoxMAC.getSelectedItem();
					textField_inputorSelectMAC.setText(null);
					if (MACs.equals("×Ö·û´®")) {
						btn_selectMAC.setVisible(false);
						textField_inputorSelectMAC.setEditable(true);
					}
					if (MACs.equals("ÎÄ¼þ")) {
						btn_selectMAC.setVisible(true);
						textField_inputorSelectMAC.setEditable(false);
					}
				}
			}
		});
		chckbx_HmacMD5 = new JCheckBox("HmacMD5");
		chckbx_HmacMD5.setBounds(11, 138, 133, 27);
		panel_MAC.add(chckbx_HmacMD5);

		chckbx_HmacSHA1 = new JCheckBox("HmacSHA1");
		chckbx_HmacSHA1.setBounds(11, 183, 133, 27);
		panel_MAC.add(chckbx_HmacSHA1);

		chckbx_HmacSHA256 = new JCheckBox("HmacSHA256");
		chckbx_HmacSHA256.setBounds(11, 224, 133, 27);
		panel_MAC.add(chckbx_HmacSHA256);

		chckbx_HmacSHA384 = new JCheckBox("HmacSHA384");
		chckbx_HmacSHA384.setBounds(10, 263, 133, 27);
		panel_MAC.add(chckbx_HmacSHA384);

		chckbx_HmacSHA512 = new JCheckBox("HmacSHA512");
		chckbx_HmacSHA512.setBounds(11, 301, 133, 27);
		panel_MAC.add(chckbx_HmacSHA512);

		chckbx_HmacMD2 = new JCheckBox("HmacMD2");
		chckbx_HmacMD2.setBounds(11, 341, 133, 27);
		panel_MAC.add(chckbx_HmacMD2);

		chckbx_HmacMD4 = new JCheckBox("HmacMD4");
		chckbx_HmacMD4.setBounds(10, 379, 133, 27);
		panel_MAC.add(chckbx_HmacMD4);

		chckbx_HmacRipeMD128 = new JCheckBox("HmacRipeMD128");
		chckbx_HmacRipeMD128.setBounds(9, 414, 133, 27);
		panel_MAC.add(chckbx_HmacRipeMD128);

		chckbx_HmacRipeMD160 = new JCheckBox("HmacRipeMD160");
		chckbx_HmacRipeMD160.setBounds(11, 449, 133, 27);
		panel_MAC.add(chckbx_HmacRipeMD160);

		chckbx_HmacSHA224 = new JCheckBox("HmacSHA224");
		chckbx_HmacSHA224.setBounds(11, 486, 133, 27);
		panel_MAC.add(chckbx_HmacSHA224);

		chckbx_HmacTiger = new JCheckBox("Hmac-Tiger");
		chckbx_HmacTiger.setBounds(11, 518, 122, 27);
		panel_MAC.add(chckbx_HmacTiger);

		textField_HmacMD5 = new JTextField();
		textField_HmacMD5.setEditable(false);
		textField_HmacMD5.setColumns(10);
		textField_HmacMD5.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacMD5.setBounds(150, 139, 351, 24);
		panel_MAC.add(textField_HmacMD5);

		textField_HmacSHA1 = new JTextField();
		textField_HmacSHA1.setEditable(false);
		textField_HmacSHA1.setColumns(10);
		textField_HmacSHA1.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacSHA1.setBounds(150, 184, 355, 24);
		panel_MAC.add(textField_HmacSHA1);

		textField_HmacSHA256 = new JTextField();
		textField_HmacSHA256.setEditable(false);
		textField_HmacSHA256.setColumns(10);
		textField_HmacSHA256.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacSHA256.setBounds(150, 227, 355, 24);
		panel_MAC.add(textField_HmacSHA256);

		textField_HmacSHA384 = new JTextField();
		textField_HmacSHA384.setEditable(false);
		textField_HmacSHA384.setColumns(10);
		textField_HmacSHA384.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacSHA384.setBounds(150, 261, 355, 24);
		panel_MAC.add(textField_HmacSHA384);

		textField_HmacSHA512 = new JTextField();
		textField_HmacSHA512.setEditable(false);
		textField_HmacSHA512.setColumns(10);
		textField_HmacSHA512.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacSHA512.setBounds(150, 302, 355, 24);
		panel_MAC.add(textField_HmacSHA512);

		textField_HmacMD2 = new JTextField();
		textField_HmacMD2.setEditable(false);
		textField_HmacMD2.setColumns(10);
		textField_HmacMD2.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacMD2.setBounds(150, 339, 355, 24);
		panel_MAC.add(textField_HmacMD2);

		textField_HmacMD4 = new JTextField();
		textField_HmacMD4.setEditable(false);
		textField_HmacMD4.setColumns(10);
		textField_HmacMD4.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacMD4.setBounds(150, 380, 355, 24);
		panel_MAC.add(textField_HmacMD4);

		textField_HmacRipeMD128 = new JTextField();
		textField_HmacRipeMD128.setEditable(false);
		textField_HmacRipeMD128.setColumns(10);
		textField_HmacRipeMD128.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacRipeMD128.setBounds(150, 414, 355, 24);
		panel_MAC.add(textField_HmacRipeMD128);

		textField_HmacRipeMD160 = new JTextField();
		textField_HmacRipeMD160.setEditable(false);
		textField_HmacRipeMD160.setColumns(10);
		textField_HmacRipeMD160.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacRipeMD160.setBounds(150, 453, 355, 24);
		panel_MAC.add(textField_HmacRipeMD160);

		textField_HmacSHA224 = new JTextField();
		textField_HmacSHA224.setEditable(false);
		textField_HmacSHA224.setColumns(10);
		textField_HmacSHA224.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacSHA224.setBounds(150, 487, 355, 24);
		panel_MAC.add(textField_HmacSHA224);

		// JTextField[]
		// textFields={textField_HmacMD5,textField_HmacSHA1,textField_HmacSHA256,textField_HmacSHA384,textField_HmacSHA512,
		// textField_HmacMD2,textField_HmacMD4,textField_HmacRipeMD128,textField_HmacRipeMD160,textField_HmacSHA224,textField_HmacTiger};
		// JCheckBox[]
		// checkBoxs={chckbx_HmacMD5,chckbx_HmacSHA1,chckbx_HmacSHA256,chckbx_HmacSHA384,chckbx_HmacSHA512,chckbx_HmacMD2,chckbx_HmacMD4,
		// chckbx_HmacRipeMD128,chckbx_HmacRipeMD160,chckbx_HmacSHA224,chckbx_HmacTiger};
		button_MACclac = new JButton("\u8BA1\u7B97");
		button_MACclac.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				textField_HmacMD2.setText("");
				textField_HmacMD4.setText("");
				textField_HmacMD5.setText("");
				textField_HmacRipeMD128.setText("");
				textField_HmacRipeMD160.setText("");
				textField_HmacSHA224.setText("");
				textField_HmacSHA1.setText("");
				textField_HmacSHA256.setText("");
				textField_HmacSHA384.setText("");
				textField_HmacSHA512.setText("");
				textField_HmacTiger.setText("");
				String msg = textField_inputorSelectMAC.getText();
				if (chckbx_HmacTiger.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacTiger.setText(MACCoder.encodeHmacTigerFile(msg,key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacTiger.setText(MACCoder.encodeHmacTiger(msg,key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}						
					}
				}
				if (chckbx_HmacMD5.isSelected()) {
					String key=textField_MACkey.getText();
					try {
						if (MACs.equals("ÎÄ¼þ")) {
							textField_HmacMD5.setText(MACCoder.encodeHmacMD5File(msg, key));
						}
						else {
							textField_HmacMD5.setText(MACCoder.encodeHmacMD5(msg,key));						
						}
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA1.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacSHA1.setText(MACCoder.encodeHmacSHAFile(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacSHA1.setText(MACCoder.encodeHmacSHA(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}						
					}
				}
				if (chckbx_HmacSHA256.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacSHA256.setText(MACCoder.encodeHmacSHA256File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacSHA256.setText(MACCoder.encodeHmacSHA256(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}						
					}
				}
				if (chckbx_HmacSHA384.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacSHA384.setText(MACCoder.encodeHmacSHA384File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacSHA384.setText(MACCoder.encodeHmacSHA384(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}						
					}
				}
				if (chckbx_HmacSHA512.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacSHA512.setText(MACCoder.encodeHmacSHA512File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacSHA512.setText(MACCoder.encodeHmacSHA512(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}					
					}
				}
				if (chckbx_HmacMD2.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacMD2.setText(MACCoder.encodeHmacMD2File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacMD2.setText(MACCoder.encodeHmacMD2(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}					
					}
				}
				if (chckbx_HmacMD4.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacMD4.setText(MACCoder.encodeHmacMD4File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacMD4.setText(MACCoder.encodeHmacMD4(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}					
					}
				}
				if (chckbx_HmacRipeMD128.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacRipeMD128.setText(MACCoder.encodeHmacRipeMD128File(msg, key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacRipeMD128.setText(MACCoder.encodeHmacRipeMD128(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}				
					}
				}
				if (chckbx_HmacRipeMD160.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacRipeMD160.setText(MACCoder.encodeHmacRipeMD160File(msg,key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacRipeMD160.setText(MACCoder.encodeHmacRipeMD160(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}				
					}
				}
				if (chckbx_HmacSHA224.isSelected()) {
					String key=textField_MACkey.getText();
					if (MACs.equals("ÎÄ¼þ")) {
						try {
							textField_HmacSHA224.setText(MACCoder.encodeHmacSHA224File(msg,key));
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					else {
						try {
							textField_HmacSHA224.setText(MACCoder.encodeHmacSHA224(msg,key));
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (Exception e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}				
					}
				}
			}
		});
		button_MACclac.setBounds(38, 573, 113, 27);
		panel_MAC.add(button_MACclac);

		button_MACclear = new JButton("\u6E05\u96F6");
		button_MACclear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				textField_HmacMD2.setText("");
				textField_HmacMD4.setText("");
				textField_HmacMD5.setText("");
				textField_HmacRipeMD128.setText("");
				textField_HmacRipeMD160.setText("");
				textField_HmacSHA224.setText("");
				textField_HmacSHA1.setText("");
				textField_HmacSHA256.setText("");
				textField_HmacSHA384.setText("");
				textField_HmacSHA512.setText("");
				textField_HmacTiger.setText("");
				chckbx_HmacMD2.setSelected(false);
				chckbx_HmacMD4.setSelected(false);
				chckbx_HmacMD5.setSelected(false);
				chckbx_HmacRipeMD128.setSelected(false);
				chckbx_HmacRipeMD160.setSelected(false);
				chckbx_HmacSHA1.setSelected(false);
				chckbx_HmacSHA224.setSelected(false);
				chckbx_HmacSHA384.setSelected(false);
				chckbx_HmacSHA256.setSelected(false);
				chckbx_HmacTiger.setSelected(false);
				chckbx_HmacSHA512.setSelected(false);
				textField_inputorSelectMAC.setText("");
			}
		});
		button_MACclear.setBounds(367, 573, 113, 27);
		panel_MAC.add(button_MACclear);

		textField_HmacTiger = new JTextField();
		textField_HmacTiger.setEditable(false);
		textField_HmacTiger.setColumns(10);
		textField_HmacTiger.setBorder(new SoftBevelBorder(BevelBorder.LOWERED, null, null, null, null));
		textField_HmacTiger.setBounds(150, 519, 355, 24);
		panel_MAC.add(textField_HmacTiger);
		
		JLabel lblkey = new JLabel("\u8BF7\u8F93\u5165key:");
		lblkey.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 16));
		lblkey.setBounds(40, 94, 95, 24);
		panel_MAC.add(lblkey);
		
		textField_MACkey = new JTextField();
		textField_MACkey.setBounds(148, 95, 332, 24);
		panel_MAC.add(textField_MACkey);
		textField_MACkey.setColumns(10);

		JPanel panel_Test = new JPanel();
		tabbedPane.addTab("ÐÔÄÜ²âÊÔ", null, panel_Test, null);
		panel_Test.setLayout(null);

		tabbedPane_1 = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane_1.setBounds(0, 0, 549, 624);
		panel_Test.add(tabbedPane_1);

		panel_AES = new JPanel();
		tabbedPane_1.addTab("AESËã·¨²âÊÔ", null, panel_AES, null);
		panel_AES.setLayout(null);

		JLabel lblNewLabel = new JLabel("\u9009\u62E9\u52A0\u5BC6\u5F3A\u5EA6\uFF08\u5BC6\u94A5\u957F\u5EA6\uFF09:");
		lblNewLabel.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblNewLabel.setBounds(14, 13, 249, 31);
		panel_AES.add(lblNewLabel);

		textField_AES10M = new JTextField();
		textField_AES10M.setEditable(false);
		textField_AES10M.setBounds(14, 141, 272, 24);
		panel_AES.add(textField_AES10M);
		textField_AES10M.setColumns(10);

		textField_AES100M = new JTextField();
		textField_AES100M.setEditable(false);
		textField_AES100M.setColumns(10);
		textField_AES100M.setBounds(14, 222, 272, 24);
		panel_AES.add(textField_AES100M);

		textField_AES500M = new JTextField();
		textField_AES500M.setEditable(false);
		textField_AES500M.setColumns(10);
		textField_AES500M.setBounds(14, 303, 272, 24);
		panel_AES.add(textField_AES500M);

		JRadioButton rdbtn_testAES128 = new JRadioButton("128");
		rdbtn_testAES128.setBounds(33, 61, 64, 27);
		panel_AES.add(rdbtn_testAES128);

		JRadioButton rdbtn_testAES192 = new JRadioButton("192");
		rdbtn_testAES192.setBounds(155, 61, 64, 27);
		panel_AES.add(rdbtn_testAES192);

		JRadioButton rdbtn_testAES256 = new JRadioButton("256");
		rdbtn_testAES256.setBounds(283, 61, 64, 27);
		panel_AES.add(rdbtn_testAES256);
		
		ButtonGroup group2=new ButtonGroup();
		group2.add(rdbtn_testAES128);
		group2.add(rdbtn_testAES192);
		group2.add(rdbtn_testAES256);
		
		JLabel lblm = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A10M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblm.setBounds(14, 97, 249, 31);
		panel_AES.add(lblm);

		JLabel lblm_1 = new JLabel(
				"\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A100M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_1.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblm_1.setBounds(14, 178, 249, 31);
		panel_AES.add(lblm_1);

		JLabel lblm_2 = new JLabel(
				"\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A500M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_2.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblm_2.setBounds(14, 259, 249, 31);
		panel_AES.add(lblm_2);

		JButton btn_selectAES10M = new JButton("...");
		btn_selectAES10M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_AES10M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectAES10M.setBounds(300, 140, 23, 27);
		panel_AES.add(btn_selectAES10M);

		JButton btn_selectAES100M = new JButton("...");
		btn_selectAES100M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_AES100M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectAES100M.setBounds(300, 221, 23, 27);
		panel_AES.add(btn_selectAES100M);

		JButton btn_selectAES500M = new JButton("...");
		btn_selectAES500M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_AES500M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectAES500M.setBounds(300, 302, 23, 27);
		panel_AES.add(btn_selectAES500M);

		JLabel lblg = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A1G\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblg.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblg.setBounds(14, 340, 249, 31);
		panel_AES.add(lblg);

		textField_AES1G = new JTextField();
		textField_AES1G.setEditable(false);
		textField_AES1G.setColumns(10);
		textField_AES1G.setBounds(14, 384, 272, 24);
		panel_AES.add(textField_AES1G);

		JButton btn_selectAES1G = new JButton("...");
		btn_selectAES1G.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_AES1G.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectAES1G.setBounds(300, 383, 23, 27);
		panel_AES.add(btn_selectAES1G);
		
		textField_AEStime10M = new JTextField();
		textField_AEStime10M.setEditable(false);
		textField_AEStime10M.setBounds(368, 141, 112, 24);
		panel_AES.add(textField_AEStime10M);
		textField_AEStime10M.setColumns(10);
		
		textField_AEStime100M = new JTextField();
		textField_AEStime100M.setEditable(false);
		textField_AEStime100M.setColumns(10);
		textField_AEStime100M.setBounds(368, 222, 112, 24);
		panel_AES.add(textField_AEStime100M);
		
		textField_AEStime500M = new JTextField();
		textField_AEStime500M.setEditable(false);
		textField_AEStime500M.setColumns(10);
		textField_AEStime500M.setBounds(368, 303, 112, 24);
		panel_AES.add(textField_AEStime500M);
		
		textField_AEStime1G = new JTextField();
		textField_AEStime1G.setEditable(false);
		textField_AEStime1G.setColumns(10);
		textField_AEStime1G.setBounds(368, 384, 112, 24);
		panel_AES.add(textField_AEStime1G);
		
		label_12 = new JLabel("\u52A0\u5BC6\u65F6\u95F4\uFF1A");
		label_12.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_12.setBounds(350, 97, 112, 31);
		panel_AES.add(label_12);
		
		btn_TestAES = new JButton("\u6267\u884C\u52A0\u5BC6");
		btn_TestAES.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String getAESlength = null;
				if (rdbtn_testAES128.isSelected()) {
					getAESlength=rdbtn_testAES128.getText();
				}
				if (rdbtn_testAES192.isSelected()) {
					getAESlength=rdbtn_testAES192.getText();
				}
				if (rdbtn_testAES256.isSelected()) {
					getAESlength=rdbtn_testAES256.getText();
				}
				try {
					long timeAES10M=TestTime.TestTimebyAES(textField_AES10M.getText(), textField_AES10M.getText()+".enc", getAESlength);
					long timeAES100M=TestTime.TestTimebyAES(textField_AES100M.getText(), textField_AES100M.getText()+".enc", getAESlength);
					long timeAES500M=TestTime.TestTimebyAES(textField_AES500M.getText(), textField_AES500M.getText()+".enc", getAESlength);
					long timeAES1G=TestTime.TestTimebyAES(textField_AES1G.getText(), textField_AES1G.getText()+".enc", getAESlength);
					textField_AEStime10M.setText(String.valueOf(timeAES10M));
					textField_AEStime100M.setText(String.valueOf(timeAES100M));
					textField_AEStime500M.setText(String.valueOf(timeAES500M));
					textField_AEStime1G.setText(String.valueOf(timeAES1G));
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
		btn_TestAES.setBounds(190, 476, 113, 27);
		panel_AES.add(btn_TestAES);

		panel_2 = new JPanel();
		tabbedPane_1.addTab("HASHËã·¨²âÊÔ", null, panel_2, null);
		panel_2.setLayout(null);
		
		label_13 = new JLabel("\u9009\u62E9\u7B97\u6CD5\u957F\u5EA6:");
		label_13.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_13.setBounds(14, 13, 249, 31);
		panel_2.add(label_13);
		
		rdbtn_SHA1 = new JRadioButton("SHA1");
		rdbtn_SHA1.setBounds(24, 53, 87, 27);
		panel_2.add(rdbtn_SHA1);
		
		rdbtn_SHA256 = new JRadioButton("SHA-256");
		rdbtn_SHA256.setBounds(117, 53, 87, 27);
		panel_2.add(rdbtn_SHA256);
		
		rdbtn_SHA384 = new JRadioButton("SHA-384");
		rdbtn_SHA384.setBounds(210, 53, 87, 27);
		panel_2.add(rdbtn_SHA384);
		
		rdbtn_SHA512 = new JRadioButton("SHA-512");
		rdbtn_SHA512.setBounds(303, 53, 87, 27);
		panel_2.add(rdbtn_SHA512);
		
		ButtonGroup group3=new ButtonGroup();
		group3.add(rdbtn_SHA1);
		group3.add(rdbtn_SHA256);
		group3.add(rdbtn_SHA384);
		group3.add(rdbtn_SHA512);
		
		label_14 = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A10M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		label_14.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_14.setBounds(14, 103, 249, 31);
		panel_2.add(label_14);
		
		lblm_3 = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A100M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_3.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblm_3.setBounds(14, 184, 249, 31);
		panel_2.add(lblm_3);
		
		textField_HASH10M = new JTextField();
		textField_HASH10M.setEditable(false);
		textField_HASH10M.setColumns(10);
		textField_HASH10M.setBounds(14, 147, 272, 24);
		panel_2.add(textField_HASH10M);
		
		textField_HASH100M = new JTextField();
		textField_HASH100M.setEditable(false);
		textField_HASH100M.setColumns(10);
		textField_HASH100M.setBounds(14, 228, 272, 24);
		panel_2.add(textField_HASH100M);
		
		lblm_4 = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A500M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_4.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblm_4.setBounds(14, 265, 249, 31);
		panel_2.add(lblm_4);
		
		textField_HASH500M = new JTextField();
		textField_HASH500M.setEditable(false);
		textField_HASH500M.setColumns(10);
		textField_HASH500M.setBounds(14, 309, 272, 24);
		panel_2.add(textField_HASH500M);
		
		lblg_1 = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A1G\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblg_1.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		lblg_1.setBounds(14, 346, 249, 31);
		panel_2.add(lblg_1);
		
		textField_HASH1G = new JTextField();
		textField_HASH1G.setEditable(false);
		textField_HASH1G.setColumns(10);
		textField_HASH1G.setBounds(14, 392, 272, 24);
		panel_2.add(textField_HASH1G);
		
		btn_selectHash10M = new JButton(",,.");
		btn_selectHash10M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_HASH10M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectHash10M.setBounds(299, 146, 26, 27);
		panel_2.add(btn_selectHash10M);
		
		btn_selectHash100M = new JButton(",,.");
		btn_selectHash100M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_HASH100M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectHash100M.setBounds(299, 227, 26, 27);
		panel_2.add(btn_selectHash100M);
		
		btn_selectHash500M = new JButton(",,.");
		btn_selectHash500M.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_HASH500M.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectHash500M.setBounds(299, 308, 26, 27);
		panel_2.add(btn_selectHash500M);
		
		btn_selectHash1G = new JButton(",,.");
		btn_selectHash1G.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser fileChooser = new JFileChooser("D:");
				if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					textField_HASH1G.setText(fileChooser.getSelectedFile().getPath());
				}
			}
		});
		btn_selectHash1G.setBounds(299, 391, 26, 27);
		panel_2.add(btn_selectHash1G);
		
		textField_timeHash10M = new JTextField();
		textField_timeHash10M.setEditable(false);
		textField_timeHash10M.setColumns(10);
		textField_timeHash10M.setBounds(366, 147, 112, 24);
		panel_2.add(textField_timeHash10M);
		
		textField_timeHash100M = new JTextField();
		textField_timeHash100M.setEditable(false);
		textField_timeHash100M.setColumns(10);
		textField_timeHash100M.setBounds(366, 228, 112, 24);
		panel_2.add(textField_timeHash100M);
		
		textField_timeHash500M = new JTextField();
		textField_timeHash500M.setEditable(false);
		textField_timeHash500M.setColumns(10);
		textField_timeHash500M.setBounds(366, 309, 112, 24);
		panel_2.add(textField_timeHash500M);
		
		textField_timeHash1G = new JTextField();
		textField_timeHash1G.setEditable(false);
		textField_timeHash1G.setColumns(10);
		textField_timeHash1G.setBounds(366, 392, 112, 24);
		panel_2.add(textField_timeHash1G);
		
		label_18 = new JLabel("\u8BA1\u7B97\u65F6\u95F4:");
		label_18.setFont(new Font("Î¢ÈíÑÅºÚ", Font.PLAIN, 15));
		label_18.setBounds(331, 103, 147, 31);
		panel_2.add(label_18);
		
		btn_TestHash = new JButton("\u6267\u884C\u8BA1\u7B97");
		btn_TestHash.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String getAlgorithms = null;
				if (rdbtn_SHA1.isSelected()) {
					getAlgorithms=rdbtn_SHA1.getText();
				}
				if (rdbtn_SHA256.isSelected()) {
					getAlgorithms=rdbtn_SHA256.getText();
				}
				if (rdbtn_SHA384.isSelected()) {
					getAlgorithms=rdbtn_SHA384.getText();
				}
				if (rdbtn_SHA512.isSelected()) {
					getAlgorithms=rdbtn_SHA512.getText();
				}
				try {
					long timeHASH10M=TestTime.TestTimebyHash(textField_HASH10M.getText(), getAlgorithms);
					long timeHASH100M=TestTime.TestTimebyHash(textField_HASH100M.getText(),getAlgorithms);
					long timeHASH500M=TestTime.TestTimebyHash(textField_HASH500M.getText(),getAlgorithms);
					long timeHASH1G=TestTime.TestTimebyHash(textField_HASH1G.getText(),getAlgorithms);
					textField_timeHash10M.setText(String.valueOf(timeHASH10M));
					textField_timeHash100M.setText(String.valueOf(timeHASH100M));
					textField_timeHash500M.setText(String.valueOf(timeHASH500M));
					textField_timeHash1G.setText(String.valueOf(timeHASH1G));
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		});
		btn_TestHash.setBounds(184, 483, 113, 27);
		panel_2.add(btn_TestHash);

	}
}
