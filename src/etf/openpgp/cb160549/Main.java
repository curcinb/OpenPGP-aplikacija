package etf.openpgp.cb160549;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;


public class Main extends JFrame {

	/**
	 * JPanel-i za funkcionalnosti aplikacije
	 */
	private JPanel dodavanjeBrisanje;
	private JPanel prijemPoruke;
	private JPanel slanjePoruke;
	private JPanel javniKljucevi;
	private JPanel privatniKljucevi;
	
	/**
	 * Liste javnih i privatnih kljuceva
	 */
	public static DefaultListModel privateKeys;
	public static DefaultListModel publicKeys;

	/**
	 * Konsturktor, inicijalizuje polja klase
	 */
	public Main() {
		publicKeys = new DefaultListModel();
		privateKeys = new DefaultListModel();
		dodavanjeBrisanje = new DodavanjeBrisanje();
		javniKljucevi = new JavniKljucevi();
		privatniKljucevi = new PrivatniKljucevi();
		prijemPoruke = new PrijemPoruke();
		slanjePoruke = new SlanjePoruke();
		setDefaultCloseOperation(EXIT_ON_CLOSE);
		initMenu();
		setLayout(new BorderLayout());
		changePanel(dodavanjeBrisanje);
	}

	/**
	 * Akcija menija, obradjue dogadjaje promene panela
	 *
	 */
	private class MenuAction implements ActionListener {

		private JPanel panel;

		private MenuAction(JPanel pnl) {
			this.panel = pnl;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			changePanel(panel);

		}

	}

	/**
	 * Inicijalizacija GUI-a aplikacije
	 */
	private void initMenu() {
		setTitle("ZP projekat 2020");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(200, 200, 700, 700);

		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);

		JMenu mnMenu = new JMenu("Menu");
		menuBar.add(mnMenu);

		JMenuItem mntmGenerisanjeBrisanje = new JMenuItem("Generisanje / brisanje");
		mnMenu.add(mntmGenerisanjeBrisanje);
		mntmGenerisanjeBrisanje.addActionListener(new MenuAction(dodavanjeBrisanje));

		JMenuItem mntmSlanjePoruke = new JMenuItem("Slanje poruke");
		mnMenu.add(mntmSlanjePoruke);
		mntmSlanjePoruke.addActionListener(new MenuAction(slanjePoruke));

		JMenuItem mntmPrijemPoruke = new JMenuItem("Prijem poruke");
		mnMenu.add(mntmPrijemPoruke);
		mntmPrijemPoruke.addActionListener(new MenuAction(prijemPoruke));

		JMenuItem mntmJavniKljucevi = new JMenuItem("Javni kljucevi");
		mnMenu.add(mntmJavniKljucevi);
		mntmJavniKljucevi.addActionListener(new MenuAction(javniKljucevi));

		JMenuItem mntmPrivatniKljucevi = new JMenuItem("Privatni kljucevi");
		mnMenu.add(mntmPrivatniKljucevi);
		mntmPrivatniKljucevi.addActionListener(new MenuAction(privatniKljucevi));

	}

	/**
	 * Obrada promene vidljivog panela
	 * @param panel Panel za promenu
	 */
	private void changePanel(JPanel panel) {
		updatePubKeysList();
		updatePrivKeysList();
		try {
			panel = panel.getClass().newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
		}

		getContentPane().removeAll();
		getContentPane().add(panel, BorderLayout.CENTER);
		getContentPane().doLayout();
		update(getGraphics());
		revalidate();
	}

	public static void updatePubKeysList() {
		publicKeys.clear();
		for (PPGPPrstenJavnihKljuceva k : PrstenKljuceva.getPublicKeys())
			publicKeys.addElement(k);
	}

	public static void updatePrivKeysList() {
		privateKeys.clear();
		for (PPGPPrstenTajnihKljuceva k : PrstenKljuceva.getPrivateKeys())
			privateKeys.addElement(k);
	}

	/**
	 * Glavna nit aplikacije
	 * @param args
	 */
	public static void main(String[] args) {
		Main frame = new Main();
		frame.setBounds(200, 200, 950, 700);
		frame.setVisible(true);
		frame.setLocationRelativeTo(null);
	}
}
