package etf.openpgp.cb160549;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Vector;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileSystemView;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class SlanjePoruke extends JPanel {

	
	/**
	 * GUI polja za korisnicki unos
	 */
	private JTextField textField;
	private JPasswordField passwordField;
	JList rsaTajnost;
	JScrollPane lista;
	JComboBox rsaEnkripcija;
	JComboBox choice;
	JCheckBox checkZip;
	JCheckBox checkRadix;
	JCheckBox checkAutPot;
	JCheckBox checkEnkTaj;

	/**
	 * Konstruktor, inicijalizacija
	 */
	public SlanjePoruke() {

		this.setBorder(new EmptyBorder(5, 5, 5, 5));
		this.setLayout(null);

		JLabel lblUnesiPoruku = new JLabel("Unesi poruku:");
		lblUnesiPoruku.setBounds(48, 40, 96, 14);
		this.add(lblUnesiPoruku);

		textField = new JTextField();
		textField.setBounds(211, 37, 669, 20);
		this.add(textField);
		textField.setColumns(10);

		JLabel lblTajnost = new JLabel("Enkripcija:");
		lblTajnost.setBounds(48, 84, 46, 14);
		this.add(lblTajnost);

		checkEnkTaj = new JCheckBox();
		checkEnkTaj.setBounds(130, 80, 97, 23);
		checkEnkTaj.setSelected(true);
		checkEnkTaj.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					checkZip.setEnabled(true);
					checkRadix.setEnabled(true);

					if (checkEnkTaj.isSelected()) {
						choice.setEnabled(true);
						rsaTajnost.setEnabled(true);
					} else {
						choice.setEnabled(false);
						rsaTajnost.setEnabled(false);
					}

					if ((!checkEnkTaj.isSelected()) && checkAutPot.isSelected()) {
						checkZip.setSelected(false);
						checkZip.setEnabled(false);
						checkRadix.setSelected(true);
						checkRadix.setEnabled(false);
					}

				} catch (Exception ex) {

					ex.printStackTrace();
				}
			}
		});
		this.add(checkEnkTaj);

		JSeparator separator = new JSeparator();
		separator.setBounds(48, 109, 78, 2);
		this.add(separator);

		JLabel lblOdaberiAlgoritam = new JLabel("Odaberi algoritam:");
		lblOdaberiAlgoritam.setBounds(48, 137, 143, 14);
		this.add(lblOdaberiAlgoritam);

		String[] choiceString = { "3DES", "CAST5" };
		choice = new JComboBox(choiceString);
		choice.setBounds(211, 134, 134, 20);
		this.add(choice);

		JLabel lblOdaberiRsaKljuckljuceve = new JLabel("Odaberi RSA kljuc/kljuceve:");
		lblOdaberiRsaKljuckljuceve.setBounds(401, 137, 250, 14);
		this.add(lblOdaberiRsaKljuckljuceve);

		rsaTajnost = new JList();
		lista = new JScrollPane(rsaTajnost);
		lista.setBounds(600, 134, 280, 100);
		this.add(lista);

		JLabel lblAutenticnost = new JLabel("Autentikacija:");
		lblAutenticnost.setBounds(48, 212, 78, 14);
		this.add(lblAutenticnost);

		checkAutPot = new JCheckBox();
		checkAutPot.setBounds(130, 208, 97, 23);
		checkAutPot.setSelected(true);
		checkAutPot.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					checkZip.setEnabled(true);
					checkRadix.setEnabled(true);

					if (checkAutPot.isSelected()) {
						rsaEnkripcija.setEnabled(true);
						passwordField.setEnabled(true);
					} else {
						rsaEnkripcija.setEnabled(false);
						passwordField.setEnabled(false);
					}

					if ((!checkEnkTaj.isSelected()) && checkAutPot.isSelected()) {
						checkZip.setSelected(false);
						checkZip.setEnabled(false);
						checkRadix.setSelected(true);
						checkRadix.setEnabled(false);
					}
				} catch (Exception ex) {

					ex.printStackTrace();
				}
			}
		});
		this.add(checkAutPot);

		JSeparator separator_1 = new JSeparator();
		separator_1.setBounds(48, 237, 78, 2);
		this.add(separator_1);

		JLabel lblNewLabel = new JLabel("Privatni RSA kljuc:");
		lblNewLabel.setBounds(48, 262, 120, 14);
		this.add(lblNewLabel);

		JLabel lblUnesiLozinku = new JLabel("Unesi lozinku:");
		lblUnesiLozinku.setBounds(48, 300, 104, 14);
		this.add(lblUnesiLozinku);

		passwordField = new JPasswordField();
		passwordField.setBounds(211, 300, 134, 20);
		this.add(passwordField);

		rsaEnkripcija = new JComboBox();
		rsaEnkripcija.setBounds(211, 259, 250, 20);
		this.add(rsaEnkripcija);

		JLabel lblOdaberi = new JLabel("Odaberi:");
		lblOdaberi.setBounds(48, 352, 59, 14);
		this.add(lblOdaberi);

		checkZip = new JCheckBox("ZIP kompresija");
		checkZip.setBounds(211, 348, 120, 23);
		this.add(checkZip);

		checkRadix = new JCheckBox("Radix64 konverzija");
		checkRadix.setBounds(401, 348, 149, 23);
		this.add(checkRadix);

		class FileChooser extends JFrame implements ActionListener {
			@Override
			public void actionPerformed(ActionEvent evt) {
				// if the user presses the save button show the save dialog
				String com = evt.getActionCommand();
				if (com.equals("Posalji poruku")) {
					// create an object of JFileChooser class
					JFileChooser j = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
					// invoke the showsSaveDialog function to show the save dialog
					int r = j.showSaveDialog(null);
					// if the user selects a file
					if (r == JFileChooser.APPROVE_OPTION) {
						// set the label to the path of the selected file
						// l.setText(j.getSelectedFile().getAbsolutePath());
					}
					// if the user cancelled the operation
					else {
						// l.setText("the user cancelled the operation");
					}
				}
			}
		}
		FileChooser l1 = new FileChooser();

		JButton button = new JButton("Posalji poruku");
		button.setBounds(600, 352, 116, 22);
		button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					boolean enkTaj = checkEnkTaj.isSelected();
					boolean autPot = checkAutPot.isSelected();
					boolean zip = checkZip.isSelected();
					boolean radix = checkRadix.isSelected();

					if (!enkTaj && !autPot)
						return;

					if (enkTaj) { // Tajnost = enkripcija
						try {
							if (rsaTajnost.getSelectedValuesList().size() == 0)
								return;
							String algoritam = choice.getSelectedItem().toString();

							PGPSecretKey signKey = null;
							char[] signPasswd = null;

							String textToEnc = textField.getText();

							if (autPot) {
								// Encrypt & Sign
								signKey = ((PPGPPrstenTajnihKljuceva) rsaEnkripcija.getSelectedItem()).getSigningKey();
								String passwd = new String(passwordField.getPassword());
								zip = true;
								if (passwd == null)
									return;
								signPasswd = passwd.toCharArray();
							}

							Vector<PGPPublicKey> recipients = new Vector<PGPPublicKey>();

							ArrayList<PPGPPrstenJavnihKljuceva> lista = (ArrayList<PPGPPrstenJavnihKljuceva>) rsaTajnost
									.getSelectedValuesList();

							for (PPGPPrstenJavnihKljuceva kr : lista)
								recipients.add(kr.getEncryptionKey());

							File tmpFile = File.createTempFile("enc", ".txt");
							FileOutputStream plain_out = new FileOutputStream(tmpFile);
							plain_out.write(textToEnc.getBytes("UTF8"));
							plain_out.close();

							File outFile = chooseFile();
							FileOutputStream fout = new FileOutputStream(outFile);
							Enkripter.encryptFile(fout, tmpFile.getAbsolutePath(), recipients, radix, signKey,
									signPasswd, zip, algoritam);
							fout.close();

							tmpFile.delete();

						} catch (Exception ex) {
							ex.printStackTrace();
						}
					} else { // Potpisivanje
						try {
							// radix = true;
							String textToSign = textField.getText();

							String passwd = new String(passwordField.getPassword());
							if (passwd == null)
								return;

							PGPSecretKey sigKey = ((PPGPPrstenTajnihKljuceva) rsaEnkripcija.getSelectedItem())
									.getSigningKey();

							String sText = Potpisivac.signText(textToSign, sigKey, passwd.toCharArray(), zip, radix);
							File poruka = chooseFile();
							FileOutputStream plain_out = new FileOutputStream(poruka);
							plain_out.write(sText.getBytes());
							plain_out.close();

						} catch (Exception ex) {
							ex.printStackTrace();
						}
					}

				} catch (Exception ex) {

					ex.printStackTrace();
				}
			}
		});
		this.add(button);

		// Na kraju inita
		updatePubKeysList();
		updatePrivKeysList();
	}

	/**
	 * Odabirac fajlova
	 * @return Odabrani fajl
	 */
	public File chooseFile() {
		JFileChooser chooser = new JFileChooser();
		chooser.setDialogTitle("Odaberi fajl");
		if (chooser.showSaveDialog((JFrame) SwingUtilities.getWindowAncestor(this)) != JFileChooser.APPROVE_OPTION)
			return null;
		return chooser.getSelectedFile();
	}

	public SlanjePoruke(boolean b) {
		updatePubKeysList();
		updatePrivKeysList();
	}

	/**
	 * Apdejtovanje liste javnih kljuceva
	 */
	public void updatePubKeysList() {
		Main.updatePubKeysList();

		DefaultComboBoxModel encMod = new DefaultComboBoxModel(Main.publicKeys.toArray());

		rsaTajnost.setModel(encMod);
	}

	
	/**
	 * Apdtejtovanje liste privatnih kljuceva 
	 */
	public void updatePrivKeysList() {
		Main.updatePrivKeysList();

		DefaultComboBoxModel encSignModel = new DefaultComboBoxModel(Main.privateKeys.toArray());
		rsaEnkripcija.setModel(encSignModel);

	}

}
