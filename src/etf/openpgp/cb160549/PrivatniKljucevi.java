package etf.openpgp.cb160549;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.EmptyBorder;

public class PrivatniKljucevi extends JPanel {

	/**
	 *  Lista tajnih kljuceva
	 */
	private JList rsaEnkripcija;
	/**
	 * 	GUI element za ispis
	 */
	JScrollPane lista;
	

	
	/**
	 * Konstruktorm, inicijalizacija
	 */
	public PrivatniKljucevi() {

		this.setBorder(new EmptyBorder(5, 5, 5, 5));
		this.setLayout(null);

		JLabel lblPgpPrstenJavnih = new JLabel("PGP prsten privatnih kljuceva");
		lblPgpPrstenJavnih.setBounds(400, 160, 200, 14);
		this.add(lblPgpPrstenJavnih);

		rsaEnkripcija = new JList();
		lista = new JScrollPane(rsaEnkripcija);
		lista.setBounds(250, 200, 450, 221);
		this.add(lista);

		updatePrivKeysList();
	}

	/**
	 * Apdejtovanje liste privatnih kljuceva
	 */
	public void updatePrivKeysList() {
		Main.updatePrivKeysList();
		DefaultComboBoxModel encSignModel = new DefaultComboBoxModel(Main.privateKeys.toArray());
		rsaEnkripcija.setModel(encSignModel);

	}

}
