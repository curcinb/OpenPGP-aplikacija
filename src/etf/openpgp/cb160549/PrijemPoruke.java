package etf.openpgp.cb160549;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.swing.JButton;
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

public class PrijemPoruke extends JPanel {

	/**
	 * Tekstualno polje za unos putanje do zeljenog fajla za dekripciju
	 */
	private JTextField putanja;
	/**
	 * 	Lozinka za privatni kljuc kojim je fajl enkriptovan
	 */
	private JPasswordField lozinka;
	/**
	 * Tekstualno polje za ispis putanje odabranog fajla za proveru potpisa
	 */
	private JTextField putanjaPotpisa;

	/**
	 * Konstruktor, inicijalizacija GUI-ja
	 */
	public PrijemPoruke() {
		this.setBorder(new EmptyBorder(5, 5, 5, 5));
		this.setLayout(null);

		JLabel lblBrisanjeKljuca = new JLabel("Dekripcija:");
		lblBrisanjeKljuca.setBounds(42, 38, 220, 14);
		this.add(lblBrisanjeKljuca);

		JSeparator separator_1 = new JSeparator();
		separator_1.setBounds(42, 63, 114, 2);
		this.add(separator_1);

		JLabel lblOdaberiKljuc = new JLabel("Odaberi kriptovani fajl:");
		lblOdaberiKljuc.setBounds(42, 89, 200, 14);
		this.add(lblOdaberiKljuc);

		JButton btnOdaberi = new JButton("Odaberi...");
		btnOdaberi.setBounds(203, 85, 119, 23);
		add(btnOdaberi);
		btnOdaberi.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				putanja.setText(chooseFile().getAbsolutePath());
			}
		});

		putanja = new JTextField();
		putanja.setBounds(42, 136, 280, 20);
		this.add(putanja);

		JLabel lblUnesiLozinku_1 = new JLabel("Lozinka:");
		lblUnesiLozinku_1.setBounds(42, 183, 70, 14);
		this.add(lblUnesiLozinku_1);

		lozinka = new JPasswordField();
		lozinka.setBounds(137, 180, 185, 20);
		this.add(lozinka);

		JButton btnDekriptuj = new JButton("Dekriptuj");
		btnDekriptuj.setBounds(137, 272, 89, 23);
		add(btnDekriptuj);
		btnDekriptuj.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					String passwd = new String(lozinka.getPassword());
					if (passwd == null)
						return;

					RezultatDekripcije decryptionResult;

					File tmpFile = File.createTempFile("dcx", ".dec");

					FileOutputStream fout = new FileOutputStream(tmpFile);
					FileInputStream fin = new FileInputStream(putanja.getText());

					decryptionResult = Dekripter.decryptFile(fin, passwd.toCharArray(), fout);

					fin.close();
					fout.close();

					if (confirmDecryption(decryptionResult)) {
						File target = chooseFile();
						
						InputStream in = new FileInputStream(tmpFile);
						OutputStream out = new FileOutputStream(target);

						byte[] buf = new byte[1024];
						int len;
						while ((len = in.read(buf)) > 0) {
							out.write(buf, 0, len);
						}
						in.close();
						out.close();
					}

					tmpFile.delete();

				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		});

		JLabel lblVerifikacijaKljuca = new JLabel("Verifikacija:");
		lblVerifikacijaKljuca.setBounds(400, 38, 220, 14);
		this.add(lblVerifikacijaKljuca);

		JSeparator separator_2 = new JSeparator();
		separator_2.setBounds(400, 63, 114, 2);
		this.add(separator_2);

		JLabel lblOdaberiFajl = new JLabel("Odaberi fajl sa potpisom:");
		lblOdaberiFajl.setBounds(400, 89, 200, 14);
		this.add(lblOdaberiFajl);

		JButton btnOdaberi2 = new JButton("Odaberi...");
		btnOdaberi2.setBounds(561, 85, 119, 23);
		add(btnOdaberi2);
		btnOdaberi2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				putanjaPotpisa.setText(chooseFile().getAbsolutePath());
			}
		});

		putanjaPotpisa = new JTextField();
		putanjaPotpisa.setBounds(400, 136, 280, 20);
		this.add(putanjaPotpisa);

		JButton btnVerifikuj = new JButton("Verifikuj");
		btnVerifikuj.setBounds(495, 272, 89, 23);
		add(btnVerifikuj);
		btnVerifikuj.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				try {
					String res = null;

					FileInputStream fsignin = new FileInputStream(putanjaPotpisa.getText());

					String content = "";
					try {
						content = new String(Files.readAllBytes(Paths.get(putanjaPotpisa.getText())));
					} catch (IOException e) {
						e.printStackTrace();
					}

					res = Verifikator.verifyText(content);
					fsignin.close();

					confirmVerification(res);
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		});

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

	/**
	 * Metoda koja prikazuje uspesnost dekripcije
	 * @param res	Rezultat dekripcije
	 * @return	Boolean vrednost 
	 */
	boolean confirmDecryption(RezultatDekripcije res) {
		if (!res.isIsSigned())
			return true;
		else if (res.isIsSigned() && res.isIsSignatureValid()) {
			JOptionPane.showMessageDialog((JFrame) SwingUtilities.getWindowAncestor(this),
					"Verifikacija potpisa uspesna" + res.getSignee());
			return true;
		} else
			return (JOptionPane.showConfirmDialog((JFrame) SwingUtilities.getWindowAncestor(this),
					"Verifikacija potpisa NEUSPESNA" + res.getSignatureException().getMessage()
							+ ".\n Da li zelis da nastavis?",
					"Warning", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.YES_OPTION);
	}

	void confirmVerification(String res) {
		if (res != null)
			JOptionPane.showMessageDialog((JFrame) SwingUtilities.getWindowAncestor(this),
					"Verifikacija potpisa uspesna" + res, "Ok", JOptionPane.INFORMATION_MESSAGE);
		else
			JOptionPane.showMessageDialog((JFrame) SwingUtilities.getWindowAncestor(this),
					"Verifikacija potpisa NEUSPESNA", "Error", JOptionPane.ERROR_MESSAGE);
	}
}
