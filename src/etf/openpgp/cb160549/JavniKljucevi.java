package etf.openpgp.cb160549;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;

public class JavniKljucevi extends JPanel {

	/**
	 * Lista javnih kljuceva
	 */
	private JList rsaTajnost;
	/**
	 * GUI element za ispis
	 */
	JScrollPane lista;

	/**
	 * Konstruktor, inicijalizuje GUI elemente
	 */
	public JavniKljucevi() {
		this.setBorder(new EmptyBorder(5, 5, 5, 5));
		this.setLayout(null);

		JLabel lblPgpPrstenJavnih = new JLabel("PGP prsten javnih kljuceva");
		lblPgpPrstenJavnih.setBounds(400, 160, 200, 14);
		this.add(lblPgpPrstenJavnih);

		rsaTajnost = new JList();
		lista = new JScrollPane(rsaTajnost);
		lista.setBounds(250, 200, 450, 221);
		this.add(lista);

		updatePubKeysList();
	}

	/**
	 * Apdejtovanje liste javnih kljuceva
	 */
	public void updatePubKeysList() {
		Main.updatePubKeysList();
		DefaultComboBoxModel encMod = new DefaultComboBoxModel(Main.publicKeys.toArray());
		rsaTajnost.setModel(encMod);
	}
}
