
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
	String s = "字符串";
	String MACs = "字符串";
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
	private JLabel label_2;
	private JRadioButton rdbtn_decrypt128;
	private JRadioButton rdbtn_decrypt192;
	private JRadioButton rdbtn_decrypt256;
	private JRadioButton rdbtn_encrypt128;
	private JRadioButton rdbtn_encrypt192;
	private JRadioButton rdbtn_encrypt256;
	private JLabel label_3;
	String items[] = { "字符串", "文件" };
	private JButton btn_choosefileHash;
	private JPasswordField passwordField_encrypt1;
	private JPasswordField passwordField_encrypt2;
	private JPasswordField passwordField_decrypt;
	private JTextField textField_sign;
	private JTextField textField_select_verify;
	private JTextField textField_Select_signValue;
	private JPasswordField passwordField_passwordsign;
	private JPasswordField passwordField_passwordsign2;
	private JPasswordField passwordField_verify;
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
	private JPanel panel_1;
	private JPanel panel_2;
	private JTextField textField_1;
	private JTextField textField_2;
	private JTextField textField_3;
	private JTextField textField_4;

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
		tabbedPane.addTab("HASH值计算", null, panel_hash, null);
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
					if (s.equals("文件")) {
						try {
							FileInputStream fis=new FileInputStream(file);
							Security.addProvider(new BouncyCastleProvider());
							//消息摘要值 - 水流
							MessageDigest md=MessageDigest.getInstance("SHA-256");
							//消息摘要输入流 - 装了水表的水管
							DigestInputStream dis=new DigestInputStream(fis, md);
							
							
							FileInputStream in = new FileInputStream(textField_message.getText());
							byte[] buffer = new byte[4096];
							while (in.read(buffer) != -1)
								;
							msg = buffer;
							in.close();
						} catch (FileNotFoundException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
					}
					if (chckbx_MD5.isSelected()) {
						md = MessageDigest.getInstance("MD5");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_MD5.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA1.isSelected()) {
						md = MessageDigest.getInstance("SHA1");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA1.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_224.isSelected()) {
						md = MessageDigest.getInstance("SHA-224");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA_224.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_256.isSelected()) {
						md = MessageDigest.getInstance("SHA-256");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA_256.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_384.isSelected()) {
						md = MessageDigest.getInstance("SHA-384");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA_384.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA_512.isSelected()) {
						md = MessageDigest.getInstance("SHA-512");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA_512.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_224.isSelected()) {
						md = MessageDigest.getInstance("SHA3-224");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA3_224.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_256.isSelected()) {
						md = MessageDigest.getInstance("SHA3-256");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA3_256.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_384.isSelected()) {
						md = MessageDigest.getInstance("SHA3-384");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA3_384.setText(Hex.toHexString(hashValue).toUpperCase());
					}
					if (chckbx_SHA3_512.isSelected()) {
						md = MessageDigest.getInstance("SHA3-512");
						md.update(msg);
						byte[] hashValue = md.digest();
						textField_SHA3_512.setText(Hex.toHexString(hashValue).toUpperCase());
					}
				} catch (NoSuchAlgorithmException e1) {
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
					if (s.equals("字符串")) {
						btn_choosefileHash.setVisible(false);
						textField_message.setEditable(true);
					}
					if (s.equals("文件")) {
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
		tabbedPane.addTab("文件加解密", null, panel_fileDE, null);
		panel_fileDE.setLayout(null);

		JLabel encry = new JLabel("\u6587\u4EF6\u52A0\u5BC6:");
		encry.setFont(new Font("微软雅黑", Font.BOLD, 18));
		encry.setBounds(14, 13, 99, 26);
		panel_fileDE.add(encry);

		JLabel decry = new JLabel("\u6587\u4EF6\u89E3\u5BC6:");
		decry.setFont(new Font("微软雅黑", Font.BOLD, 18));
		decry.setBounds(14, 335, 99, 26);
		panel_fileDE.add(decry);

		JLabel password1 = new JLabel("\u5BC6\u7801:");
		password1.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		password1.setBounds(14, 162, 80, 26);
		panel_fileDE.add(password1);

		JLabel password2 = new JLabel("\u786E\u8BA4\u5BC6\u7801:");
		password2.setFont(new Font("微软雅黑", Font.PLAIN, 15));
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
						JOptionPane.showMessageDialog(null, "密码不能为空！");
					}
					try {
						MyFileEncryptor.enryptFile(encryfilename, encryptfilename, password, encrypt_length);
						JOptionPane.showMessageDialog(null, "加密成功！");
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					JOptionPane.showMessageDialog(null, "两次输入口令不一致，请重新输入！");
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
		label.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		label.setBounds(14, 484, 80, 26);
		panel_fileDE.add(label);

		JButton button_decry = new JButton("\u89E3\u5BC6");
		button_decry.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String decryfilename = textField_choosefile_decrypt.getText();
				String after_decryfilename = textField_choosefile_decrypt.getText() + ".txt";
				char[] password_char = passwordField_decrypt.getPassword();
				String password = new String(password_char);
				int decrypt_length = 0;
				if (rdbtn_decrypt128.isSelected()) {
					decrypt_length = Integer.parseInt(rdbtn_decrypt128.getText());
				}
				if (rdbtn_decrypt192.isSelected()) {
					decrypt_length = Integer.parseInt(rdbtn_decrypt192.getText());
				}
				if (rdbtn_decrypt256.isSelected()) {
					decrypt_length = Integer.parseInt(rdbtn_decrypt256.getText());
				}
				try {
					MyFileEncryptor.decryptFile(decryfilename, after_decryfilename, password, decrypt_length);
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		button_decry.setBounds(198, 548, 80, 27);
		panel_fileDE.add(button_decry);

		JLabel label_1 = new JLabel("\u8BF7\u9009\u62E9\u52A0\u5BC6\u957F\u5EA6:");
		label_1.setFont(new Font("微软雅黑", Font.PLAIN, 15));
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

		label_2 = new JLabel("\u8BF7\u9009\u62E9\u52A0\u5BC6\u957F\u5EA6:");
		label_2.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		label_2.setBounds(10, 413, 217, 26);
		panel_fileDE.add(label_2);

		rdbtn_decrypt128 = new JRadioButton("128");
		rdbtn_decrypt128.setBounds(14, 448, 80, 27);
		panel_fileDE.add(rdbtn_decrypt128);

		rdbtn_decrypt192 = new JRadioButton("192");
		rdbtn_decrypt192.setBounds(105, 448, 89, 27);
		panel_fileDE.add(rdbtn_decrypt192);

		rdbtn_decrypt256 = new JRadioButton("256");
		rdbtn_decrypt256.setBounds(205, 448, 89, 27);
		panel_fileDE.add(rdbtn_decrypt256);

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(rdbtn_decrypt128);
		buttonGroup.add(rdbtn_decrypt192);
		buttonGroup.add(rdbtn_decrypt256);
		label_3 = new JLabel("\uFF08\u8BF7\u8F93\u5165\u957F\u5EA6\u4E3A6-16\u4F4D\u7684\u5BC6\u7801\uFF09");
		label_3.setFont(new Font("宋体", Font.PLAIN, 15));
		label_3.setBounds(246, 232, 217, 26);
		panel_fileDE.add(label_3);

		passwordField_encrypt1 = new JPasswordField();
		passwordField_encrypt1.setBounds(108, 163, 288, 24);
		panel_fileDE.add(passwordField_encrypt1);

		passwordField_encrypt2 = new JPasswordField();
		passwordField_encrypt2.setBounds(108, 202, 288, 24);
		panel_fileDE.add(passwordField_encrypt2);

		passwordField_decrypt = new JPasswordField();
		passwordField_decrypt.setBounds(108, 485, 288, 24);
		panel_fileDE.add(passwordField_decrypt);

		JPanel panel_fileSign = new JPanel();
		tabbedPane.addTab("文件签名", null, panel_fileSign, null);
		panel_fileSign.setLayout(null);

		JLabel sign = new JLabel("\u6587\u4EF6\u7B7E\u540D:");
		sign.setFont(new Font("微软雅黑", Font.BOLD, 18));
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
		label_4.setFont(new Font("微软雅黑", Font.PLAIN, 15));
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
						JOptionPane.showMessageDialog(null, "密码不能为空！");
					}
					try {
						TestGenerateCert.geterateKey(password);
						TestFileSignature.signFile(signFile, signFile + ".sig", password);
						JOptionPane.showMessageDialog(null, "签名成功！");
					} catch (Exception e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				} else {
					JOptionPane.showMessageDialog(null, "两次输入口令不一致，请重新输入！");
					passwordField_encrypt1.setText("");
					passwordField_encrypt2.setText("");
				}
			}
		});
		button_sign.setBounds(177, 245, 113, 27);
		panel_fileSign.add(button_sign);

		JLabel label_5 = new JLabel("\u7B7E\u540D\u9A8C\u8BC1:");
		label_5.setFont(new Font("微软雅黑", Font.BOLD, 18));
		label_5.setBounds(19, 286, 99, 26);
		panel_fileSign.add(label_5);

		JLabel label_6 = new JLabel("\u786E\u8BA4\u5BC6\u7801:");
		label_6.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		label_6.setBounds(19, 174, 77, 26);
		panel_fileSign.add(label_6);

		textField_select_verify = new JTextField();
		textField_select_verify.setEditable(false);
		textField_select_verify.setColumns(10);
		textField_select_verify.setBounds(29, 331, 427, 24);
		panel_fileSign.add(textField_select_verify);

		JLabel label_7 = new JLabel("\uFF08\u9009\u62E9\u8981\u8FDB\u884C\u7B7E\u540D\u7684\u6587\u4EF6\uFF09");
		label_7.setFont(new Font("宋体", Font.PLAIN, 13));
		label_7.setBounds(309, 80, 215, 26);
		panel_fileSign.add(label_7);

		JLabel label_8 = new JLabel("\uFF08\u9009\u62E9\u8981\u9A8C\u8BC1\u7B7E\u540D\u7684\u6587\u4EF6\uFF09");
		label_8.setFont(new Font("宋体", Font.PLAIN, 13));
		label_8.setBounds(309, 357, 215, 26);
		panel_fileSign.add(label_8);

		textField_Select_signValue = new JTextField();
		textField_Select_signValue.setEditable(false);
		textField_Select_signValue.setColumns(10);
		textField_Select_signValue.setBounds(29, 396, 427, 24);
		panel_fileSign.add(textField_Select_signValue);

		JLabel label_9 = new JLabel("\uFF08\u9009\u62E9\u50A8\u5B58\u7B7E\u540D\u503C\u7684\u6587\u4EF6\uFF09");
		label_9.setFont(new Font("宋体", Font.PLAIN, 13));
		label_9.setBounds(309, 426, 215, 26);
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
		button_select_verify2.setBounds(470, 395, 25, 27);
		panel_fileSign.add(button_select_verify2);

		JLabel label_10 = new JLabel("\u8F93\u5165\u5BC6\u7801:");
		label_10.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		label_10.setBounds(19, 472, 77, 26);
		panel_fileSign.add(label_10);

		JButton button_verify = new JButton("\u7B7E\u540D\u9A8C\u8BC1");
		button_verify.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String verifyFile = textField_select_verify.getText();
				String signValueFile = textField_Select_signValue.getText();
				char[] password0 = passwordField_verify.getPassword();
				String password = new String(password0);
				try {
					boolean judge = TestFileSignature.verifiFile(verifyFile, signValueFile, password);
					if (judge) {
						JOptionPane.showMessageDialog(null, "验证成功！");
					}
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});
		button_verify.setBounds(177, 543, 113, 27);
		panel_fileSign.add(button_verify);

		passwordField_passwordsign = new JPasswordField();
		passwordField_passwordsign.setBounds(122, 120, 322, 24);
		panel_fileSign.add(passwordField_passwordsign);

		passwordField_passwordsign2 = new JPasswordField();
		passwordField_passwordsign2.setBounds(122, 175, 322, 24);
		panel_fileSign.add(passwordField_passwordsign2);

		passwordField_verify = new JPasswordField();
		passwordField_verify.setBounds(122, 473, 322, 24);
		panel_fileSign.add(passwordField_verify);

		label_11 = new JLabel("\uFF08\u8BF7\u8F93\u5165\u957F\u5EA6\u4E3A6-16\u4F4D\u7684\u5BC6\u7801\uFF09");
		label_11.setFont(new Font("宋体", Font.PLAIN, 13));
		label_11.setBounds(309, 204, 217, 26);
		panel_fileSign.add(label_11);

		JPanel panel_MAC = new JPanel();
		tabbedPane.addTab("消息认证码", null, panel_MAC, null);
		panel_MAC.setLayout(null);
		JComboBox comboBoxMAC = new JComboBox(items);
		comboBoxMAC.setBounds(40, 43, 72, 24);
		panel_MAC.add(comboBoxMAC);

		textField_inputorSelectMAC = new JTextField();
		textField_inputorSelectMAC.setBounds(150, 43, 330, 24);
		panel_MAC.add(textField_inputorSelectMAC);
		textField_inputorSelectMAC.setColumns(10);

		JButton btn_selectMAC = new JButton("...");
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
					if (MACs.equals("字符串")) {
						btn_selectMAC.setVisible(false);
						textField_inputorSelectMAC.setEditable(true);
					}
					if (MACs.equals("文件")) {
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
				byte msg[] = textField_inputorSelectMAC.getText().getBytes();
				if (MACs.equals("文件")) {
					try {
						FileInputStream in = new FileInputStream(textField_inputorSelectMAC.getText());
						byte[] buffer = new byte[4096];
						while (in.read(buffer) != -1)
							;
						msg = buffer;
						in.close();
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				if (chckbx_HmacTiger.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacTigerKey();
						textField_HmacTiger.setText(MACCoder.encodeHmacTiger(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacMD5.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacMD5Key();
						textField_HmacMD5.setText(MACCoder.encodeHmacMD5(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA1.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacSHAKey();
						textField_HmacSHA1.setText(MACCoder.encodeHmacSHA(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA256.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacSHA256Key();
						textField_HmacSHA256.setText(MACCoder.encodeHmacSHA256(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA384.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacSHA384Key();
						textField_HmacSHA384.setText(MACCoder.encodeHmacSHA384(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA512.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacSHA512Key();
						textField_HmacSHA512.setText(MACCoder.encodeHmacSHA512(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacMD2.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacMD2Key();
						textField_HmacMD2.setText(MACCoder.encodeHmacMD2(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacMD4.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacMD4Key();
						textField_HmacMD4.setText(MACCoder.encodeHmacMD4(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacRipeMD128.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacRipeMD128Key();
						textField_HmacRipeMD128.setText(MACCoder.encodeHmacRipeMD128(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacRipeMD160.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacRipeMD160Key();
						textField_HmacRipeMD160.setText(MACCoder.encodeHmacRipeMD160(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				if (chckbx_HmacSHA224.isSelected()) {
					try {
						byte[] key = MACCoder.initHmacSHA224Key();
						textField_HmacSHA224.setText(MACCoder.encodeHmacSHA224(key, msg));
					} catch (NoSuchAlgorithmException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
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

		JPanel panel_Test = new JPanel();
		tabbedPane.addTab("性能测试", null, panel_Test, null);
		panel_Test.setLayout(null);

		tabbedPane_1 = new JTabbedPane(JTabbedPane.TOP);
		tabbedPane_1.setBounds(0, 0, 538, 613);
		panel_Test.add(tabbedPane_1);

		panel_1 = new JPanel();
		tabbedPane_1.addTab("AES算法测试", null, panel_1, null);
		panel_1.setLayout(null);

		JLabel lblNewLabel = new JLabel("\u9009\u62E9\u52A0\u5BC6\u5F3A\u5EA6\uFF08\u5BC6\u94A5\u957F\u5EA6\uFF09:");
		lblNewLabel.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		lblNewLabel.setBounds(14, 13, 249, 31);
		panel_1.add(lblNewLabel);

		textField_1 = new JTextField();
		textField_1.setBounds(14, 141, 272, 24);
		panel_1.add(textField_1);
		textField_1.setColumns(10);

		textField_2 = new JTextField();
		textField_2.setColumns(10);
		textField_2.setBounds(14, 222, 272, 24);
		panel_1.add(textField_2);

		textField_3 = new JTextField();
		textField_3.setColumns(10);
		textField_3.setBounds(14, 303, 272, 24);
		panel_1.add(textField_3);

		JRadioButton rdbtnNewRadioButton = new JRadioButton("128");
		rdbtnNewRadioButton.setBounds(33, 61, 64, 27);
		panel_1.add(rdbtnNewRadioButton);

		JRadioButton radioButton = new JRadioButton("192");
		radioButton.setBounds(155, 61, 64, 27);
		panel_1.add(radioButton);

		JRadioButton radioButton_1 = new JRadioButton("256");
		radioButton_1.setBounds(283, 61, 64, 27);
		panel_1.add(radioButton_1);

		JLabel lblm = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A10M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		lblm.setBounds(14, 97, 249, 31);
		panel_1.add(lblm);

		JLabel lblm_1 = new JLabel(
				"\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A100M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_1.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		lblm_1.setBounds(14, 178, 249, 31);
		panel_1.add(lblm_1);

		JLabel lblm_2 = new JLabel(
				"\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A500M\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblm_2.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		lblm_2.setBounds(14, 259, 249, 31);
		panel_1.add(lblm_2);

		JButton btnNewButton = new JButton("...");
		btnNewButton.setBounds(300, 140, 23, 27);
		panel_1.add(btnNewButton);

		JButton button = new JButton("...");
		button.setBounds(300, 221, 23, 27);
		panel_1.add(button);

		JButton button_1 = new JButton("...");
		button_1.setBounds(300, 302, 23, 27);
		panel_1.add(button_1);

		JLabel lblg = new JLabel("\u8BF7\u9009\u62E9\u4E00\u4E2A\u5927\u5C0F\u4E3A1G\u5DE6\u53F3\u7684\u6587\u4EF6:");
		lblg.setFont(new Font("微软雅黑", Font.PLAIN, 15));
		lblg.setBounds(14, 340, 249, 31);
		panel_1.add(lblg);

		textField_4 = new JTextField();
		textField_4.setColumns(10);
		textField_4.setBounds(14, 384, 272, 24);
		panel_1.add(textField_4);

		JButton button_2 = new JButton("...");
		button_2.setBounds(300, 383, 23, 27);
		panel_1.add(button_2);

		panel_2 = new JPanel();
		tabbedPane_1.addTab("HASH算法测试", null, panel_2, null);

	}
}
