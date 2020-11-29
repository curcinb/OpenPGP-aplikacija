package etf.openpgp.cb160549;

import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileFilter;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;


public class DodavanjeBrisanje extends JPanel {

	/**
	 * Unos imena korisnika za kreiranje novog para kljuceva
	 */
	private JTextField imeTextField;
	/**
	 * Unos mejla korisnika za kreiranje novog para kljuceva
	 */
	private JTextField mejlTextField;
	/**
	 * Unos lozinke korisnika za kreiranje novog para kljuceva
	 */
	private JPasswordField passwordField;
	/**
	 * Unos lozinke kljuca za brisanje kljuca iz prstena
	 */
	private JPasswordField deleteKeyPasswordField;
	/**
	 * Lista javnih kljuceva koji mogu da se obrisu
	 */
	private JComboBox brisanjeJCh;// Brisanje javnog
	/**
	 * Lista javnih kljuceva koji mogu da se eksportuju
	 */
	private JComboBox exportJCh;// Export javnog
	/**
	 * Lista privatnih kljuceva koji mogu da se obrisu
	 */
	private JComboBox brisanjePCh;// Brisanje privatnog
	/**
	 * Lista privatnih kljuceva koji mogu da se e
	 */
	private JComboBox exportPCh;// Export privatnog
	/**
	 * Da li se importuje privatni ili javni kljuc
	 */
	private JCheckBox chckbxNewCheckBox;// Da li je kljuc privatan
	/**
	 * Poruka o uspehu/neuspehu
	 */
	private JLabel poruka;

	/**
	 * Hash Mapa koja cuva lozinke
	 */
	private HashMap<String, String> lozinke = new HashMap<>();

	/**
	 * Konstruktor klase u kojem se inicijalizuju GUI elementi
	 */
	@SuppressWarnings("deprecation")
	public DodavanjeBrisanje() {
		this.setBorder(new EmptyBorder(5, 5, 5, 5));
		this.setLayout(null);

		JSeparator separator_4 = new JSeparator();
		separator_4.setBounds(307, 517, 0, -477);
		this.add(separator_4);

		JLabel lblGenerisanjeKljuca = new JLabel("Generisanje kljuca:");
		lblGenerisanjeKljuca.setBounds(65, 38, 122, 14);
		this.add(lblGenerisanjeKljuca);

		JLabel lblUnesiIme = new JLabel("Ime:");
		lblUnesiIme.setBounds(65, 89, 70, 14);
		this.add(lblUnesiIme);

		JLabel lblUnesiMejl = new JLabel("Mejl:");
		lblUnesiMejl.setBounds(65, 136, 70, 14);
		this.add(lblUnesiMejl);

		JLabel lblUnesiLozinku = new JLabel("Lozinka:");
		lblUnesiLozinku.setBounds(65, 183, 70, 14);
		this.add(lblUnesiLozinku);

		JLabel lblAlgoritam = new JLabel("RSA Algoritam:");
		lblAlgoritam.setBounds(65, 232, 70, 14);
		this.add(lblAlgoritam);

		imeTextField = new JTextField();
		imeTextField.setBounds(178, 86, 103, 20);
		this.add(imeTextField);
		imeTextField.setColumns(10);

		mejlTextField = new JTextField();
		mejlTextField.setBounds(178, 133, 103, 20);
		this.add(mejlTextField);
		mejlTextField.setColumns(10);

		String[] choice1String = { "1024", "2048", "4096" };
		JComboBox choice1 = new JComboBox(choice1String);
		choice1.setBounds(178, 226, 103, 20);
		this.add(choice1);

		JLabel lblBrisanjeKljuca = new JLabel("Brisanje kljuca:");
		lblBrisanjeKljuca.setBounds(342, 38, 220, 14);
		this.add(lblBrisanjeKljuca);

		JLabel lblOdaberiKljuc = new JLabel("Odaberi privatni kljuc:");
		lblOdaberiKljuc.setBounds(342, 89, 200, 14);
		this.add(lblOdaberiKljuc);

		brisanjePCh = new JComboBox();
		brisanjePCh.setBounds(342, 136, 250, 20);
		this.add(brisanjePCh);

		JLabel lblOdaberiKljuc2 = new JLabel(" Odaberi javni kljuc:");
		lblOdaberiKljuc2.setBounds(600, 89, 200, 14);
		this.add(lblOdaberiKljuc2);

		brisanjeJCh = new JComboBox();
		brisanjeJCh.setBounds(600, 136, 250, 20);
		this.add(brisanjeJCh);

		JLabel lblUnesiLozinku_1 = new JLabel("Lozinka:");
		lblUnesiLozinku_1.setBounds(342, 183, 70, 14);
		this.add(lblUnesiLozinku_1);

		passwordField = new JPasswordField();
		passwordField.setBounds(178, 180, 103, 20);
		this.add(passwordField);

		deleteKeyPasswordField = new JPasswordField();
		deleteKeyPasswordField.setBounds(437, 180, 103, 20);
		this.add(deleteKeyPasswordField);

		JLabel lblExportKljuca = new JLabel("Export kljuca:");
		lblExportKljuca.setBounds(65, 345, 80, 14);
		this.add(lblExportKljuca);

		JLabel lblImportKljuca = new JLabel("Import kljuca:");
		lblImportKljuca.setBounds(600, 345, 80, 14);
		this.add(lblImportKljuca);

		JLabel lblDaLiJe = new JLabel("Da li je kljuc privatan?");
		lblDaLiJe.setBounds(600, 396, 135, 14);
		this.add(lblDaLiJe);

		chckbxNewCheckBox = new JCheckBox("");
		chckbxNewCheckBox.setBounds(724, 383, 30, 40);
		this.add(chckbxNewCheckBox);

		JLabel lblOdaberiKljuc_1 = new JLabel("Odaberi privatni kljuc:");
		lblOdaberiKljuc_1.setBounds(65, 396, 200, 14);
		this.add(lblOdaberiKljuc_1);

		exportPCh = new JComboBox();
		exportPCh.setBounds(65, 436, 250, 20);
		this.add(exportPCh);

		JLabel lblOdaberiKljuc_2 = new JLabel("Odaberi javni kljuc:");
		lblOdaberiKljuc_2.setBounds(342, 396, 200, 14);
		this.add(lblOdaberiKljuc_2);

		exportJCh = new JComboBox();
		exportJCh.setBounds(342, 436, 250, 20);
		this.add(exportJCh);

		class AscFilter extends FileFilter {
			@Override
			public boolean accept(File pathname) {
				String filename = pathname.getName();
				if (pathname.isDirectory()) {
					return true;
				} else if (filename.endsWith("asc'")) {
					return true;
				} else {
					return false;
				}
			}

			@Override
			public String getDescription() {
				// TODO Auto-generated method stub
				return null;
			}
		}

		JButton btnExport = new JButton("Export"); // Export javnog kljuca
		btnExport.setBounds(392, 489, 89, 23);
		btnExport.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					if (Main.publicKeys.size() <= 0)
						return;
					PPGPPrstenJavnihKljuceva k = (PPGPPrstenJavnihKljuceva) Main.publicKeys
							.get(exportJCh.getSelectedIndex());
					saveKey(k.getPublicKeyRing().getEncoded());
					poruka.setText("");
				} catch (Exception ex) {
					poruka.setText("ERROR: Javni kljuc nije eksportovan.");
					ex.printStackTrace();
				}

			}
		});
		this.add(btnExport);

		JButton btnExport1 = new JButton("Export"); // Export privatnog kljuca
		btnExport1.setBounds(116, 489, 89, 23);
		btnExport1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					if (Main.privateKeys.size() <= 0)
						return;
					PPGPPrstenTajnihKljuceva k = (PPGPPrstenTajnihKljuceva) Main.privateKeys
							.get(exportPCh.getSelectedIndex());
					saveKey(k.getSecretKeyRing().getEncoded());
					poruka.setText("");
				} catch (Exception ex) {
					poruka.setText("ERROR: Privatni kljuc nije eksportovan.");
					ex.printStackTrace();
				}

			}
		});
		this.add(btnExport1);

		JButton btnImport = new JButton("Import");
		btnImport.setBounds(636, 489, 89, 23);
		btnImport.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				JFileChooser chooser = new JFileChooser();

				int returnVal = chooser.showOpenDialog(null);

				if (returnVal != JFileChooser.APPROVE_OPTION)
					return;

				try {
					if (chckbxNewCheckBox.isSelected()) {
						PGPSecretKeyRing ring = PrstenKljuceva
								.importPrivateKey(new FileInputStream(chooser.getSelectedFile()));
						System.out.println("privatni");
					} else {
						PGPPublicKeyRing ring = PrstenKljuceva
								.importPublicKey(new FileInputStream(chooser.getSelectedFile()));
						System.out.println("javni");
					}
					poruka.setText("");
				} catch (Exception ex) {
					// ex.printStackTrace();
					poruka.setText("ERROR: Import nije uspeo.");
				}

				updatePrivKeysList();
				updatePubKeysList();

			}
		});
		this.add(btnImport);

		JSeparator separator = new JSeparator();
		separator.setBounds(65, 63, 114, 2);
		this.add(separator);

		JSeparator separator_1 = new JSeparator();
		separator_1.setBounds(342, 63, 114, 2);
		this.add(separator_1);

		JSeparator separator_2 = new JSeparator();
		separator_2.setBounds(65, 370, 114, 2);
		this.add(separator_2);

		JSeparator separator_3 = new JSeparator();
		separator_3.setBounds(600, 370, 114, 2);
		this.add(separator_3);

		JSeparator separator_5 = new JSeparator();
		separator_5.setBounds(307, 38, 0, 461);
		this.add(separator_5);

		poruka = new JLabel("");
		poruka.setBounds(65, 550, 200, 23);
		this.add(poruka);

		JButton btnGenerisi = new JButton("Generisi");
		btnGenerisi.setBounds(116, 272, 89, 23);
		add(btnGenerisi);
		btnGenerisi.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				String ime = imeTextField.getText();
				String mail = mejlTextField.getText();
				String lozinka = new String(passwordField.getPassword());
				int velicinaRSA = Integer.parseInt(String.valueOf(choice1.getSelectedItem()));
				System.out.println(velicinaRSA);
				String userID = ime + "< " + mail + " >";
				try {
					PrstenKljuceva.generateNewKeyPair(velicinaRSA, userID, lozinka.toCharArray());
					lozinke.put(userID, lozinka);
					updatePubKeysList();
					updatePrivKeysList();

				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
		});

		JButton btnObrisi = new JButton("Obrisi");
		btnObrisi.setBounds(392, 272, 89, 23);
		add(btnObrisi);
		btnObrisi.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					if (Main.privateKeys.size() <= 0)
						return;

					PPGPPrstenTajnihKljuceva k = (PPGPPrstenTajnihKljuceva) Main.privateKeys
							.get(brisanjePCh.getSelectedIndex());
					// String str = k.getSecretKeyRing().toString();
					// String result = str.substring(str.indexOf(" ") + 1, str.indexOf(";"));
					// String passphrase = lozinke.get(result);
					// if (passphrase == passwordField_1.getPassword().toString()) {
					PrstenKljuceva.deletePrivateKey(k.getSecretKeyRing());

					System.out.println(PrstenKljuceva.getPrivateKeys().size());
					// }
					// else
					// System.out.println("Ne valja passphrase");

					// TODO Kako proveriti lozinku

				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				updatePrivKeysList();
			}
		});

		JButton btnObrisi2 = new JButton("Obrisi");
		btnObrisi2.setBounds(636, 272, 89, 23);
		add(btnObrisi2);
		btnObrisi2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {

				try {
					if (Main.publicKeys.size() <= 0)
						return;
					PPGPPrstenJavnihKljuceva k = (PPGPPrstenJavnihKljuceva) Main.publicKeys
							.get(brisanjeJCh.getSelectedIndex());
					PrstenKljuceva.deletePublicKey(k.getPublicKeyRing());
					System.out.println(PrstenKljuceva.getPublicKeys().size());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				updatePubKeysList();
			}

		});
		// Na kraju inita
		updatePubKeysList();
		updatePrivKeysList();
	}

	/**
	 * Vrsi update liste javnih kljuceva nakon nekih promena
	 */
	public void updatePubKeysList() {
		Main.updatePubKeysList();

		DefaultComboBoxModel encMod = new DefaultComboBoxModel(Main.publicKeys.toArray());
		DefaultComboBoxModel encMod2 = new DefaultComboBoxModel(Main.publicKeys.toArray());

		brisanjeJCh.setModel(encMod);
		exportJCh.setModel(encMod2);
	}

	/**
	 * Vrsi update liste privatnih kljuceva nakon nekih promena
	 */
	public void updatePrivKeysList() {
		Main.updatePrivKeysList();

		DefaultComboBoxModel encSignModel = new DefaultComboBoxModel(Main.privateKeys.toArray());
		DefaultComboBoxModel encSignModel2 = new DefaultComboBoxModel(Main.privateKeys.toArray());
		brisanjePCh.setModel(encSignModel);
		exportPCh.setModel(encSignModel2);
	}

	/**
	 * @param data niz bajtova koji definisu kljuc
	 * @throws Exception
	 */
	private void saveKey(byte[] data) throws Exception {
		JFileChooser chooser = new JFileChooser();
		if (chooser.showSaveDialog((JFrame) SwingUtilities.getWindowAncestor(this)) != JFileChooser.APPROVE_OPTION)
			return;
		File outFile = chooser.getSelectedFile();
		FileOutputStream fout = new FileOutputStream(outFile);
		fout.write(data);
		fout.close();

		JOptionPane.showMessageDialog((JFrame) SwingUtilities.getWindowAncestor(this),
				"Eksportovano u " + outFile.getPath());
	}

}
