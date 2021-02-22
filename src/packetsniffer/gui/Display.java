package packetsniffer.gui;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import packetsniffer.Captor;
import packetsniffer.CaptorRunner;
import packetsniffer.database.DatabaseCallback;
import packetsniffer.database.DatabaseConnection;

import javax.swing.*;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.RowSorterListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

public class Display extends JFrame
{
    // Panel everything is parented to
    private JPanel parentPanel;

    // Initialize tabbedPane for the three panes (Capture, Watchlists, and Session History)
    private JTabbedPane tabbedPane;

    // Initialize main JPanel (For capture, selecting interface, etc.)
    private JPanel mainPanel;

    // ScrollPanel for the main capture table
    private JScrollPane scrollPanel;

    // Button for capturing packets that interacts with CaptorRunner
    private CaptureButton captureButton;

    // Main packet table
    private JTable packetTable;

    // Columns/headers in the main packet table
    private String[] columns = new String[]
    {
            "Time",
            "Destination IP",
            "Hostname",
            "Destination Port",
            "Protocol",
            "Bytes",
            "Packets"
    };

    // Columns/headers in the blacklist table
    private String[] watchcolumns = new String[]
    {
            "IP/Subnet",
    };

    // Columns/headers in the whitelist table
    private String[] whitelist = new String[]
    {
            "IP/Subnet",
    };

    // Columns/headers in the session's table
    private String[] sessioncolumns = new String[]
    {
            "First Seen",
            "Last Seen",
            "Destination IP",
            "Hostname",
            "Destination Port",
            "Protocol",
            "Bandwidth"
    };

    // Initialize reference variable for captor
    private CaptorRunner captor;

    // For selecting a network interface
    private JComboBox selectInterface;

    // Filter for packets
    private JTextField filterText;

    // Cell renderer to render blacklist, date formats, bandwidth formatting, etc.
    private CustomRenderer captureCellRenderer;
    private CustomRenderer sessionCellRenderer;

    // Panel for the watchlists
    private JPanel watchlist;

    // Scrollpane for blacklist
    private JScrollPane watchScroll;

    // Button to add to blacklist
    private JButton addBlacklist;

    // Table for blacklist
    private JTable wtable;

    // Scrollpane for whitelist
    private JScrollPane whiteScroll;

    // Button to add to whitelist
    private JButton addWhitelist;

    // Table for whitelist
    private JTable whitelistTable;


    // Main JPanel for session history
    private JPanel sessions;

    // ScrollPane for session history table
    private JScrollPane sessionScroll;

    // Session history table
    private JTable stable;

    // Table model for session history
    private DefaultTableModel sessionmodel;

    // Sorter so that rows in the session's history table can be sorted
    private RowSorter<TableModel> sessionSorter;

    // ComboBox for selecting the last X minutes in which you want to see session history
    private JComboBox selectTime;

    // Tray icon for when the program is minimized
    private TrayIcon trayIcon;
    private SystemTray tray;

    // Label for amount of packets
    private JLabel packetLabel;

    // Label for blacklist
    private JLabel blacklistLabel;

    // Label for whitelist
    private JLabel whitelistLabel;

    // Table model for main capture panel
    private DefaultTableModel dtm = new DefaultTableModel(0, 0) {

        @Override
        public Class getColumnClass(int column)
        {
            switch (column)
            {
                case 0:
                    return java.sql.Date.class;
                case 1:
                    return java.sql.Date.class;
                case 3:
                    return Integer.class;
                case 5:
                    return Integer.class;
                case 6:
                    return Integer.class;
                default:
                    return String.class;
            }
        }

    };

    // Table model for blacklist
    private DefaultTableModel wtm = new DefaultTableModel(0, 0);

    // Table model for whitelist
    private DefaultTableModel whitelisttm = new DefaultTableModel(0, 0);

    // Logo for program
    private ImageIcon logo = new ImageIcon("images\\logohere.png");

    // Create the presets for session history for selection
    public void filltimePresets()
    {

        ComboItem item = new ComboItem("Last 5 min", "300");
        selectTime.addItem(item);
        item = new ComboItem("Last 10 min", "600");
        selectTime.addItem(item);
        item = new ComboItem("Last 15 min", "900");
        selectTime.addItem(item);
        item = new ComboItem("Last 30 min", "1800");
        selectTime.addItem(item);
        item = new ComboItem("Last 45 min", "2700");
        selectTime.addItem(item);
        item = new ComboItem("Last 1 hour", "3600");
        selectTime.addItem(item);
        item = new ComboItem("Last 2 hours", "7200");
        selectTime.addItem(item);
        item = new ComboItem("Last 4 hours", "14400");
        selectTime.addItem(item);
        item = new ComboItem("Last 6 hours", "21600");
        selectTime.addItem(item);
        item = new ComboItem("Last 12 hours", "43200");
        selectTime.addItem(item);
        item = new ComboItem("Last 24 hours", "86400");
        selectTime.addItem(item);


    }

    // Update the session history table with the current sessions in the last X minutes (What the user currently has selected in the JComboBox)
    private void updateSessionHistoryTable()
    {
        updateSessionHistoryTable(false);
    }


    private void updateSessionHistoryTable(boolean doClear)
    {

        // Get the time selected by user
        ComboItem item = (ComboItem) selectTime.getSelectedItem();

        // Clear the JTable/session history's table (Only done when the user selects a new time preset)
        if (doClear)
        {
            sessionmodel.setRowCount(0);
        }

        String selected = item.getDescription();

        // Query to populate the session history table
        String query = String.format("SELECT dst_ip, dst_port, dst_name, protocol, SUM(bandwidth), MAX(lastseen), MIN(firstseen) as minfirst FROM sessions where (firstseen >= (strftime('%%s', 'now') - %s)) Group by dst_ip, dst_port, protocol HAVING (minfirst >= (strftime('%%s', 'now') - %s));", selected, selected);

        DatabaseConnection.QueryCallback(query, new DatabaseCallback()
        {
            @Override
            public void callbackMethod(ResultSet rs) throws SQLException
            {
                int currentRow = 0;

                // For every row get destination IP, port, canonical hostname, bandwidth, last seen, and first seen
                while(rs.next())
                {
                    String dstip = rs.getString(1);
                    int dstport = rs.getInt(2);
                    String hostname = rs.getString(3);
                    String proto = rs.getString(4);

                    float bandwidth = rs.getFloat(5);
                    long lastseen = rs.getLong(6);
                    long firstseen = rs.getLong(7);

                    // If the IP is in the whitelist, don't show it
                    if (captor.getCapture().inWhitelist(dstip))
                    {
                        continue;
                    }

                    // Bandwidth calculation
                    if ((lastseen - firstseen) != 0)
                    {
                        bandwidth = bandwidth / (lastseen - firstseen);
                    }

                    // Convert first seen to date
                    Date firstdate = new Date();
                    firstdate.setTime(firstseen*1000);

                    // Convert last seen to date
                    Date lastdate = new Date ();
                    lastdate.setTime(lastseen*1000);

                    int finalRow = currentRow;

                    currentRow++;

                    float finalBandwidth = bandwidth;


                    // Update the table on the EDT/gui thread
                    SwingUtilities.invokeLater(new Runnable()
                    {
                        @Override
                        public void run()
                        {

                            // If the number of results is more than the row count add a row
                            int rowCount = sessionmodel.getRowCount();

                            if (finalRow >= rowCount)
                            {
                                sessionmodel.addRow(new Object[]{firstdate, lastdate, dstip, hostname, dstport, proto, finalBandwidth});
                            }
                            else
                            {
                                // Set the value for the row that was given if it's not a new row
                                sessionmodel.setValueAt(firstdate, finalRow, 0);
                                sessionmodel.setValueAt(lastdate, finalRow, 1);
                                sessionmodel.setValueAt(dstip, finalRow, 2);
                                sessionmodel.setValueAt(hostname, finalRow, 3);
                                sessionmodel.setValueAt(dstport, finalRow, 4);
                                sessionmodel.setValueAt(proto, finalRow, 5);
                                sessionmodel.setValueAt(finalBandwidth, finalRow, 6);
                            }

                            // If the destination IP is in the blacklist add it to the blacklist in the custom renderer
                            if (captor.getCapture().inBlacklist(dstip))
                            {
                                sessionCellRenderer.addWarning(finalRow);
                            }
                            else
                            {
                                // Remove the warning if it's not in the blacklist
                                sessionCellRenderer.removeWarning(finalRow);
                            }
                        }


                    });
                }

                // Clear rows that have expired on the gui/EDT thread
                int finalRowCount = currentRow;
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run()
                    {

                        if (!doClear)
                        {
                            int rowCount = sessionmodel.getRowCount();

                            if (finalRowCount < rowCount)
                            {
                                sessionmodel.setRowCount(finalRowCount);
                            }
                        }
                    }
                });
            }
        });
    }

    private void loadComponents()
    {
        // Initialize custom renderers
        captureCellRenderer = new CustomRenderer();
        captureCellRenderer.setHorizontalAlignment(SwingConstants.CENTER);

        sessionCellRenderer = new CustomRenderer();
        sessionCellRenderer.setHorizontalAlignment(SwingConstants.CENTER);

        // Initialize blacklist table
        wtable = new JTable();
        wtm.setColumnIdentifiers(watchcolumns);
        wtable.setModel(wtm);


        // Initialize whitelist table
        whitelistTable = new JTable();
        whitelisttm.setColumnIdentifiers(whitelist);
        whitelistTable.setModel(whitelisttm);

        // Initialize session history table
        stable = new JTable();

        stable.getTableHeader().setReorderingAllowed(false);

        // Initialize session history table model
        sessionmodel = new DefaultTableModel(0, 0)

        {
            @Override
            public Class getColumnClass(int column)
            {
                switch (column)
                {
                    case 0:
                        return java.sql.Date.class;
                    case 1:
                        return java.sql.Date.class;
                    case 4:
                        return Integer.class;
                    case 6:
                        return Integer.class;
                    case 7:
                        return Long.class;
                    default:
                        return String.class;
                }
            }

            @Override
            public boolean isCellEditable(int row, int column) {
                //all cells false
                return false;
            }
        };

        sessionmodel.setColumnIdentifiers(sessioncolumns);
        stable.setModel(sessionmodel);
        sessionSorter = new TableRowSorter<TableModel>(sessionmodel);

        stable.setRowSorter(sessionSorter);

        // Get the session history table sorter
        DefaultRowSorter stablesort = (DefaultRowSorter)stable.getRowSorter();

        // If the table sorter is changed revalidate and repaint so the table updates
        stablesort.addRowSorterListener(new RowSorterListener() {
            @Override
            public void sorterChanged(RowSorterEvent e) {
                if (e.getType() == RowSorterEvent.Type.SORTED) {
                    // We need to call both revalidate() and repaint()
                    stable.revalidate();
                    stable.repaint();
                }
            }
        });

        // Sort the table on update
        stablesort.setSortsOnUpdates(true);

        // Timer that runs every 2 seconds to update the session history table
        Timer t = new javax.swing.Timer(2000, new ActionListener() {
            public void actionPerformed(ActionEvent e)
            {
                if (tabbedPane.getSelectedIndex() == 2)
                {
                    updateSessionHistoryTable();
                }
            }
        });

        // Make the timer repeat
        t.setRepeats(true);

        // Start the timer
        t.start();

        TableColumnModel sessionColumnModel = stable.getColumnModel();

        stable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Mouse listener so you can double click on the rows to copy the information
        stable.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() >= 2) {
                    int row = stable.getSelectedRow();

                    int columns = stable.getColumnCount();

                    String copyString = "";
                    for (int i = 0; i < columns; i++)
                    {
                        copyString += stable.getValueAt(row, i).toString();

                        if (i != (columns -1))
                        {
                            copyString += " - ";
                        }
                    }

                    StringSelection stringSelection = new StringSelection(copyString);

                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(stringSelection, null);

                    JOptionPane.showMessageDialog(null,
                            "Data copied to clipboard.");
                }
            }

        });


        // Set every column in the session history table to use the custom renderer
        sessionColumnModel.getColumn(0).setCellRenderer(sessionCellRenderer);
        sessionColumnModel.getColumn(1).setCellRenderer(sessionCellRenderer);
        sessionColumnModel.getColumn(2).setCellRenderer(sessionCellRenderer);
        sessionColumnModel.getColumn(3).setCellRenderer(sessionCellRenderer);

        sessionColumnModel.getColumn(3).setPreferredWidth(240);

        sessionColumnModel.getColumn(4).setCellRenderer(sessionCellRenderer);
        sessionColumnModel.getColumn(5).setCellRenderer(sessionCellRenderer);
        sessionColumnModel.getColumn(6).setCellRenderer(sessionCellRenderer);

        // Delete functionality for the blacklist
        Action delete = new AbstractAction()
        {
            public void actionPerformed(ActionEvent e)
            {
                int dialogResult = JOptionPane.showConfirmDialog (null, "Would You like to delete this entry?","Warning", JOptionPane.YES_NO_OPTION);

                if (dialogResult == 0)
                {
                    JTable table = (JTable) e.getSource();
                    int modelRow = Integer.valueOf(e.getActionCommand());
                    DefaultTableModel model = ((DefaultTableModel) table.getModel());

                    String ip = (String) model.getValueAt(modelRow, 0);

                    Captor captorInstance = captor.getCapture();
                    captorInstance.blacklistRemove(ip);

                    model.removeRow(modelRow);
                }
            }
        };

        // Delete functionality for the whitelist
        Action delete2 = new AbstractAction()
        {
            public void actionPerformed(ActionEvent e)
            {
                int dialogResult = JOptionPane.showConfirmDialog (null, "Would You like to delete this entry?","Warning", JOptionPane.YES_NO_OPTION);

                if (dialogResult == 0)
                {
                    JTable table = (JTable) e.getSource();
                    int modelRow = Integer.valueOf(e.getActionCommand());
                    DefaultTableModel model = ((DefaultTableModel) table.getModel());

                    String ip = (String) model.getValueAt(modelRow, 0);

                    Captor captorInstance = captor.getCapture();
                    captorInstance.whitelistRemove(ip);

                    model.removeRow(modelRow);
                }
            }
        };

        // Button columns for the blacklist
        ButtonColumn buttonColumn = new ButtonColumn(wtable, delete, 0);

        // Button columns for the whitelist
        ButtonColumn buttonColumn2 = new ButtonColumn(whitelistTable, delete2, 0);


        // Each JPanel uses a gridbag layout for dynamic sizing
        GridBagLayout gridbag = new GridBagLayout();
        GridBagConstraints con = new GridBagConstraints();

        con.fill = GridBagConstraints.BOTH;
        con.weightx = 1;
        con.weighty = 1;
        con.gridx = 0;
        con.gridy = 0;

        parentPanel = new JPanel(gridbag);

        tabbedPane = new JTabbedPane();
        tabbedPane.setTabPlacement(JTabbedPane.TOP);

        parentPanel.add(tabbedPane, con);

        mainPanel = new JPanel(gridbag);

        packetTable = new JTable()
            {
                @Override
                public boolean isCellEditable(int row, int column)
                {
                    return false;
                }
        };

        // For the main capture panel double clocking will copy information
        packetTable.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() >= 2) {
                    int row = packetTable.getSelectedRow();

                    int columns = packetTable.getColumnCount();

                    String copyString = "";
                    for (int i = 0; i < columns; i++)
                    {
                        copyString += packetTable.getValueAt(row, i).toString();

                        if (i != (columns -1))
                        {
                            copyString += " - ";
                        }
                    }

                    StringSelection stringSelection = new StringSelection(copyString);

                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(stringSelection, null);

                    JOptionPane.showMessageDialog(null,
                            "Data copied to clipboard.");
                }
            }

        });

        // Create a row sorter for the main capture packet table
        RowSorter<TableModel> sorter = new TableRowSorter<TableModel>(dtm);

        packetTable.setRowSorter(sorter);

        DefaultRowSorter dsorter = (DefaultRowSorter)packetTable.getRowSorter();

        // Make sure the main packet capture table sorts when the table is updated
        dsorter.setSortsOnUpdates(true);

        dsorter.addRowSorterListener(new RowSorterListener() {
            @Override
            public void sorterChanged(RowSorterEvent e) {
                if (e.getType() == RowSorterEvent.Type.SORTED) {
                    // We need to call both revalidate() and repaint()
                    packetTable.revalidate();
                    packetTable.repaint();
                }
            }
        });

        dtm.setColumnIdentifiers(columns);
        packetTable.setModel(dtm);


        TableColumnModel packetColumnModel = packetTable.getColumnModel();

        // Make every column in the main packet capture table use the custom renderer
        packetColumnModel.getColumn(0).setCellRenderer(captureCellRenderer);
        packetColumnModel.getColumn(1).setCellRenderer(captureCellRenderer);

        packetColumnModel.getColumn(2).setPreferredWidth(240);

        packetColumnModel.getColumn(2).setCellRenderer(captureCellRenderer);
        packetColumnModel.getColumn(3).setCellRenderer(captureCellRenderer);
        packetColumnModel.getColumn(4).setCellRenderer(captureCellRenderer);
        packetColumnModel.getColumn(5).setCellRenderer(captureCellRenderer);
        packetColumnModel.getColumn(6).setCellRenderer(captureCellRenderer);

        packetColumnModel.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        TableColumnModel watchColumnModel = wtable.getColumnModel();

        scrollPanel = new JScrollPane(packetTable);

        packetLabel = new JLabel("Packet Count: 0");

        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 0;
        con.insets = new Insets(3,3,3,3);

        // Add the packet count label to the main panel
        mainPanel.add(packetLabel, con);

        selectInterface = new JComboBox();

        con.fill = GridBagConstraints.NONE;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 1;
        con.anchor = GridBagConstraints.WEST;
        con.insets = new Insets(3,3,3,3);



        mainPanel.add(selectInterface, con);

        // Draw the placeholder text for the filter text
        filterText = new JTextField()
        {
            @Override
            protected void paintComponent(final Graphics pG)
            {
                super.paintComponent(pG);

                if (getText().length() > 0)
                {
                    return;
                }

                final Graphics2D g = (Graphics2D) pG;
                g.setRenderingHint(
                        RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g.setColor(getDisabledTextColor());
                g.drawString("Filter", getInsets().left, pG.getFontMetrics()
                        .getMaxAscent() + getInsets().top);
            }
        };

        con.fill = GridBagConstraints.BOTH;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 2;
        con.anchor = GridBagConstraints.CENTER;
        con.insets = new Insets(3,3,3,3);

        // Add filter text to the main panel
        mainPanel.add(filterText, con);

        con.insets = new Insets(3,3,3,3);

        con.anchor = GridBagConstraints.CENTER;
        con.weightx = 1;
        con.weighty = 1;
        con.fill = GridBagConstraints.BOTH;
        con.gridx = 0;
        con.gridy = 3;

        // Add scroll panel with main packet capture table to main panel
        mainPanel.add(scrollPanel, con);


        try
        {
            captor = new CaptorRunner(this);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        captureButton = new CaptureButton("Capture", this);

        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 4;

        // Add capture button to main panel
        mainPanel.add(captureButton, con);

        watchlist = new JPanel(gridbag);

        blacklistLabel = new JLabel("Blacklist");

        watchScroll = new JScrollPane(wtable);

        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 0;

        watchlist.add(blacklistLabel, con);

        con.fill = GridBagConstraints.BOTH;
        con.weightx = 1;
        con.weighty = 1;
        con.gridx = 0;
        con.gridy = 1;

        // Add blacklist table to watchlist panel
        watchlist.add(watchScroll, con);

        addBlacklist = new JButton("Add To Blacklist");
        addBlacklist.addActionListener(new ActionListener()
        {
            // Give prompt when adding to blacklist
            public void actionPerformed(ActionEvent e)
            {
                String ip = JOptionPane.showInputDialog("Blacklist", "Type the IP/Subnet");

                if (ip == null || ip.isEmpty() || ip.equalsIgnoreCase("Type the IP/Subnet"))
                {
                    return;
                }

                Captor captorInstance = captor.getCapture();

                // Add to blacklist
                captorInstance.blacklistAdd(ip);
            }
        });
        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 2;

        // Add add to blacklist button to watchlist panel
        watchlist.add(addBlacklist, con);

        whitelistLabel = new JLabel("Whitelist");

        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 3;

        // Add whitelist label to watchlist panel
        watchlist.add(whitelistLabel, con);

        whiteScroll = new JScrollPane(whitelistTable);

        con.fill = GridBagConstraints.BOTH;
        con.weightx = 1;
        con.weighty = 1;
        con.gridx = 0;
        con.gridy = 4;

        // Add whitelist table to watchlist panel
        watchlist.add(whiteScroll, con);

        addWhitelist = new JButton("Add To Whitelist");
        addWhitelist.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                // Give prompt when adding to whitelist
                String ip = JOptionPane.showInputDialog("Whitelist", "Type the IP/Subnet");

                if (ip == null || ip.isEmpty() || ip.equalsIgnoreCase("Type the IP/Subnet"))
                {
                    return;
                }

                Captor captorInstance = captor.getCapture();

                // Add to whitelist
                captorInstance.whitelistAdd(ip);
            }
        });

        con.fill = GridBagConstraints.HORIZONTAL;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 5;

        // Add whitelist to watchlist panel
        watchlist.add(addWhitelist, con);

        sessions = new JPanel(gridbag);

        sessionScroll = new JScrollPane(stable);

        con.fill = GridBagConstraints.NONE;
        con.weightx = 0;
        con.weighty = 0;
        con.gridx = 0;
        con.gridy = 0;
        con.anchor = GridBagConstraints.WEST;

        selectTime = new JComboBox();
        this.filltimePresets();

        // Select time item listener
        selectTime.addItemListener(new ItemListener()
        {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED)
                {
                    // Causes session table to do a full update and clear the table
                    updateSessionHistoryTable(true);
                }
            }
        });

        // Add select time to session history table
        sessions.add(selectTime, con);

        con.fill = GridBagConstraints.BOTH;
        con.weightx = 1;
        con.weighty = 1;
        con.gridx = 0;
        con.gridy = 1;

        // Add session history table to session history panel
        sessions.add(sessionScroll, con);

        // Add the main packet capture panel to tabbedPane
        tabbedPane.addTab("Packet Capture", mainPanel);

        // Add the watchlist panel to tabbedPane
        tabbedPane.addTab("Watchlist", watchlist);

        // Add the session history panel to tabbedPane
        tabbedPane.addTab("Session History", sessions);

        this.add(parentPanel);
    }

    // Get the main packet capture table (Used mostly in captor)
    public JTable getTable()
    {
        return this.packetTable;
    }

    // Get the interfaces that packets can be sniffed on
    public void fillInterfaces() throws PcapNativeException {
        java.util.List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        for (PcapNetworkInterface device : allDevs)
        {

            // Creates a combo item for each network interface
            ComboItem newItem = new ComboItem(device.getDescription() + " - " + device.getName(), device.getName());

            // Add the item
            this.selectInterface.addItem(newItem);
        }
    }

    // Get the selected interface
    public String getDevice()
    {
        ComboItem item = (ComboItem) this.selectInterface.getSelectedItem();
        return item.getDescription();
    }

    // Get the capture runner
    public CaptorRunner getRunner()
    {
        return this.captor;
    }

    // Add warning to main packet capture custom renderer
    public void addWarning(int row)
    {
        captureCellRenderer.addWarning(row);
    }

    // Remove warning from main packet capture custom renderer
    public void removeWarning(int row)
    {
        captureCellRenderer.removeWarning(row);
    }

    // Add entry to blacklist table
    public void addWatch(String ip)
    {
        this.wtm.addRow(new Object[]{ip});
    }

    // Add entry to whitelist table
    public void addWhitelist(String ip)
    {
        this.whitelisttm.addRow(new Object[]{ip});
    }

    // Get text in the filter text area field
    public String getFilter()
    {
        return this.filterText.getText();
    }

    // Set the packet count (Run every time a packet is sent)
    public void setPacketCount(int packetCount)
    {
        this.packetLabel.setText("Packet Count: " + packetCount);
    }

    public Display()
    {
        // Set the title of the main window
        this.setTitle("Packet Sniffer/Analyzer");
        this.setSize(1024, 600);

        Dimension preferred = new Dimension(1024, 600);
        this.setPreferredSize(preferred);

        // Sets the icon
        this.setIconImage(logo.getImage());

        // Load all the components
        this.loadComponents();

        // See if system tray is supported
        if(SystemTray.isSupported())
        {
            // Handles system tray/minimize functionality with opening/closing
            tray=SystemTray.getSystemTray();
            ActionListener exitListener=new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    System.exit(0);
                }
            };

            PopupMenu popup = new PopupMenu();
            MenuItem open = new MenuItem("Open");

            // Action listener if open is pressed when minimized in taskbar
            open.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e) {
                    setVisible(true);
                    setExtendedState(JFrame.NORMAL);
                }
            });
            popup.add(open);

            // Action listener if exit is pressed when minimized in taskbar
            MenuItem close = new MenuItem("Exit");
            close.addActionListener(exitListener);
            popup.add(close);

            trayIcon=new TrayIcon(logo.getImage(), "Packet Analyzer/Sniffer", popup);
            trayIcon.setImageAutoSize(true);

            // Moust listener for tray icon so if it's double clicked it will restore the window
            MouseListener mouseListener = new MouseListener()
            {
                @Override
                public void mouseClicked(MouseEvent e) {

                }

                @Override
                public void mousePressed(MouseEvent e)
                {
                    if (e.getClickCount() > 1)
                    {
                        setVisible(true);
                        setExtendedState(JFrame.NORMAL);
                    }
                }

                @Override
                public void mouseReleased(MouseEvent e)
                {

                }

                @Override
                public void mouseEntered(MouseEvent e)
                {

                }

                @Override
                public void mouseExited(MouseEvent e)
                {

                }
            };

            trayIcon.addMouseListener(mouseListener);

            addWindowStateListener(new WindowStateListener() {
                public void windowStateChanged(WindowEvent e) {
                    if(e.getNewState()==ICONIFIED){
                        try
                        {
                            tray.add(trayIcon);
                            setVisible(false);
                        }
                        catch (AWTException ex)
                        {
                        }
                    }
                    if(e.getNewState()==7)
                    {
                        try
                        {
                            tray.add(trayIcon);
                            setVisible(false);
                        }
                        catch(AWTException ex){
                        }
                    }

                    if(e.getNewState()==MAXIMIZED_BOTH)
                    {
                        tray.remove(trayIcon);
                        setVisible(true);
                    }

                    if(e.getNewState()==NORMAL)
                    {
                        tray.remove(trayIcon);
                        setVisible(true);
                    }
                }
            });

        }


        // Fill the interfaces once program starts
        try
        {
            this.fillInterfaces();
        }
        catch (PcapNativeException e)
        {
            e.printStackTrace();
        }

        this.setLocationRelativeTo(null);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.pack();
        this.setVisible(true);

        try
        {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        SwingUtilities.updateComponentTreeUI(this);
    }
}
