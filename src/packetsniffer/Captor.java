package packetsniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import packetsniffer.database.DatabaseCallback;
import packetsniffer.database.DatabaseConnection;
import packetsniffer.gui.Display;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.io.IOException;
import java.net.Inet4Address;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Captor
{

    // Initialize reference variable for display/gui
    private Display display;

    // Initialize reference variable for model for main capture panel
    private DefaultTableModel model;

    // Initialize int to hold the current number of packets that have come in since program started
    private int packetCount;

    // Initialize network interface variable that will hold what network adapter/device to sniff on
    private PcapNetworkInterface nif;
    private PcapHandle.Builder phb;

    // Initialize handle that will handle incoming packets
    private PcapHandle handle;

    // Initialize HashMap that holds whether we've seen the packet or not
    private HashMap<Inet4Address, HashMap<IpNumber, HashMap<Integer, Integer>>> ipMap;

    // Initialize int to see which row we're currently at as rows continue to be added.
    private int currentRow = 0;

    // Initialize blacklist and whitelist
    private Watchlists watchlists;

    // Initialize executor service/thread pool
    private ExecutorService pool;


    // Initialize hash map for hostname caching so that an ns lookup doesn't need to occur every time
    private HashMap<String, String> hostnameCache;


    // Constructor
    public Captor(Display display) throws PcapNativeException
    {
        watchlists = new Watchlists(display);
        this.display = display;

        ipMap = new HashMap<Inet4Address, HashMap<IpNumber, HashMap<Integer, Integer>>>();
        hostnameCache = new HashMap<String, String>();

        JTable table = this.display.getTable();
        model = (DefaultTableModel) table.getModel();

        // Single threaded pool so it will only create one thread
        pool = Executors.newSingleThreadExecutor();
    }

    // Add to blacklist
    public void blacklistAdd(String ips)
    {
        this.watchlists.addBlacklist(ips);
    }

    // Remove from blacklsit
    public void blacklistRemove(String ips)
    {
        this.watchlists.removeBlacklist(ips);
    }

    // Check if it's in the blacklist
    public boolean inBlacklist(String hostAddress)
    {
        return (watchlists.inBlacklist(hostAddress));
    }

    // Check if it's in the blacklist as well as remove the warning/red background
    private void checkBlacklist(String hostAddress, int data)
    {
        if (!watchlists.inBlacklist(hostAddress))
        {
            // Must remove warning on the gui thread/event dispatch thread
            SwingUtilities.invokeLater(new Runnable()
            {
                @Override
                public void run()
                {
                    display.removeWarning(data);
                }
            });

        }
        else
        {
            // Must add warning on the gui thread/event dispatch thread
            SwingUtilities.invokeLater(new Runnable()
            {
                @Override
                public void run()
                {

                    display.addWarning(data);
                }
            });
        }
    }

    // Add to whitelist
    public void whitelistAdd(String ips)
    {
        this.watchlists.addWhitelist(ips);
    }

    // Remove from whitelist
    public void whitelistRemove(String ips)
    {
        this.watchlists.removeWhitelist(ips);
    }


    // Check if it's in the whitelist
    public boolean inWhitelist(String hostAddress)
    {
        return watchlists.inWhitelist(hostAddress);
    }

    // Database session method without knowing dns hostname
    private void databaseSession(String hostAddress, int dstPort, String protoName, long len, long unix)
    {
        databaseSession(hostAddress, dstPort, protoName, len, unix, "");
    }


    // Database session method with knowing dns hostname
    private void databaseSession(String hostAddress, int dstPort, String protoName, long len, long unix, String dnsHostname)
    {
        // Initial query to see if there's been a packet from the specified destination ip, port, and protocol in the last minute
        String baseQuery = String.format("SELECT idsession from sessions where dst_ip = '%s' and dst_port=%d and protocol='%s' and (firstseen >= (strftime('%%s', 'now') - 60));", hostAddress, dstPort, protoName);
        DatabaseConnection.QueryCallback(baseQuery, new DatabaseCallback()
        {

            // Callback for insertion or update
            @Override
            public void callbackMethod(ResultSet rs)
            {
                try
                {
                    int idsession = 0;

                    if (rs.next())
                    {
                        idsession = rs.getInt(1);
                    }

                    // Add to database or update current session's bandwidth and last seen
                    if (idsession == 0)
                    {
                        String query = String.format("INSERT into sessions (dst_ip, dst_port, dst_name, protocol, bandwidth, lastseen, firstseen) VALUES ('%s', %d, '%s', '%s', %d, %d, %d);", hostAddress, dstPort, dnsHostname, protoName, len, unix, unix);
                        DatabaseConnection.QueryNoValueWait(query);
                    }
                    else
                    {
                        String query = String.format("UPDATE sessions SET lastseen = %d, bandwidth = bandwidth + %d where dst_ip = '%s' and dst_port=%d and protocol='%s' and idsession = %d", unix, len, hostAddress, dstPort, protoName, idsession);
                        DatabaseConnection.QueryNoValueWait(query);

                    }
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        });
    }

    // New session to put in the main capture panel
    private void newSession(Packet packet, IpNumber proto, int dstPort, Inet4Address dstAddress, String hostAddress, Date formattedTime, long unix, long len)
    {
        String protoName = proto.name();

        // Insert a new row on the EDT thread
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                model.addRow(new Object[]{formattedTime, hostAddress, "", dstPort, protoName, len, 1});
            }
        });


        // Checking the hash map to ensure it has the entry
        if (ipMap.containsKey(dstAddress))
        {
            HashMap innerMap = ipMap.get(dstAddress);

            if (innerMap.containsKey(dstPort))
            {
                HashMap innerInnerMap = (HashMap) innerMap.get(dstPort);

                if (!innerInnerMap.containsKey(proto))
                {
                    innerInnerMap.put(proto, currentRow);
                }
            }
            else
            {
                HashMap protoMap = new HashMap<IpNumber, Integer>();
                protoMap.put(proto, currentRow);

                innerMap.put(dstPort, protoMap);
            }
        }
        else
        {
            HashMap protoMap = new HashMap<IpNumber, Integer>();
            protoMap.put(proto, currentRow);

            HashMap portMap = new HashMap<Integer, HashMap<IpNumber, Integer>>();
            portMap.put(dstPort, protoMap);

            ipMap.put(dstAddress, portMap);
        }

        int tempCurrent = currentRow;

        // On the ns lookup thread pool, get the host name for the current IP.
        pool.execute(new Runnable()
        {
            @Override
            public void run()
            {
                // getCanonicalHostName uses the system configured dns server (https://docs.oracle.com/javase/7/docs/api/java/net/InetAddress.html#getCanonicalHostName())
                String dnshostname = dstAddress.getCanonicalHostName();

                // Put the result in the hostname cache so less ns lookups need to occur
                hostnameCache.put(hostAddress, dnshostname);

                // Set the hostname on the row it's applicable to on the EDT thread
                SwingUtilities.invokeLater(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        model.setValueAt(dnshostname, tempCurrent, 2);
                    }
                });

                // Update the hostname in the database on a separate thread responsible for database queries
                String query = String.format("UPDATE sessions set dst_name='%s' where dst_ip='%s';", dnshostname, hostAddress);

                try
                {
                    DatabaseConnection.QueryNoValue(query);
                }
                catch (SQLException e)
                {
                    e.printStackTrace();
                }
            }
        });

        // Check databasse sessions
        this.databaseSession(hostAddress, dstPort, protoName, len, unix);

        // Check the blacklist
        this.checkBlacklist(hostAddress, currentRow);

        currentRow++;
    }


    // Updating the table in the main capture panel/functionality
    private void updateSession(Packet packet, IpNumber proto, int dstPort, String hostAddress, Date formattedTime, long unix, long len, int data)
    {

        // Since it's updating, it will increase the number of packets and length on the EDT thread
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                long value = (long)model.getValueAt(data, 5);
                int numPackets = (int)model.getValueAt(data, 6) + 1;
                long newLength = value + len;

                model.setValueAt(newLength, data, 5);
                model.setValueAt(numPackets, data, 6);
                model.setValueAt(formattedTime, data, 0);
            }
        });

        // Check the cache to see if there's a dns hostname
        String dnsHostname = hostnameCache.get(hostAddress);

        // Check database session
        this.databaseSession(hostAddress, dstPort, proto.name(), len, unix, dnsHostname);

        // Check blacklist
        this.checkBlacklist(hostAddress, data);
    }

    // Function that processes the packets that come in
    public void collectData(Packet packet, Timestamp timestamp)
    {

        try
        {
            // Get the current unix time the packet came in
            long unix = timestamp.getTime()/1000;

            // Convert unix time to a date for formatting in the table
            Date currentTime = new Date();
            currentTime.setTime(unix*1000);

            // Get the IPv4 header
            IpV4Packet.IpV4Header header = packet.get(IpV4Packet.class).getHeader();

            // Get the protocol
            IpNumber proto = header.getProtocol();
            int dstPort = 0;

            // Get the length of the header
            int headerLength = header.length();

            // Subtract the length of the header from the packet length
            long len = packet.length() - headerLength;

            // Get the destination address
            Inet4Address dstAddress = header.getDstAddr();

            // Get the host address
            String hostAddress = dstAddress.getHostAddress();

            // If it's a local address or a loopback address, we don't want to analyze it at all
            if (dstAddress.isSiteLocalAddress() || dstAddress.isLoopbackAddress())
            {
                return;
            }

            // If the host address/address is in the whitelist stop processing
            if (this.inWhitelist(hostAddress))
            {
                return;
            }

            // If the protocol is TCP
            if (proto.equals(IpNumber.TCP))
            {
                // Get the destination port and subtract the length of the tcp header from the total packet length and get the destination port
                TcpPacket tcp = packet.get(TcpPacket.class);
                dstPort = tcp.getHeader().getDstPort().valueAsInt();
                len = len - tcp.getHeader().length();
            }
            else
            {
                // If the protocol is UDP subtract the length of the udp header from the total packet length and get destination port
                if (proto.equals(IpNumber.UDP))
                {
                    UdpPacket udp = packet.get(UdpPacket.class);
                    dstPort = udp.getHeader().getDstPort().valueAsInt();
                    len = len - udp.getHeader().length();
                }
                else
                {
                    // If the protocol is ICMP see if it's an echo request and subtract the header length from the packet length
                    if (proto.equals(IpNumber.ICMPV4))
                    {

                        try
                        {
                            IcmpV4EchoPacket icmp = packet.get(IcmpV4EchoPacket.class);
                            len = icmp.length() - icmp.getHeader().length();
                        }
                        catch (Exception e)
                        {
                        }
                    }
                }
            }

            // On the gui thread/EDT thread increment the packet count
            SwingUtilities.invokeLater(new Runnable()
            {
                @Override
                public void run()
                {

                    display.setPacketCount(++packetCount);
                }
            });

            // Check if the ip address is in the hash map, if not it's a new session
            boolean contain = ipMap.containsKey(dstAddress);

            if (contain != false)
            {
                HashMap innerMap = ipMap.get(dstAddress);

                boolean containTwo = innerMap.containsKey(dstPort);

                // Check if the destination port for that address is in the hashmap. If not, it's a new session.
                if (containTwo != false)
                {

                    HashMap<Integer, Integer> innerInnerMap = (HashMap)innerMap.get(dstPort);

                    // Check if the protocol for that ip and destination port are in the hasmpa. If not it's a new session.
                    boolean containThree = innerInnerMap.containsKey(proto);

                    if (containThree != false)
                    {
                        int data = innerInnerMap.get(proto);

                        // Update the main capture table since it's not new
                        updateSession(packet, proto, dstPort, hostAddress, currentTime, unix, len, data);
                    }
                    else
                    {
                        // Insert a row in the main capture panel since it's new
                        newSession(packet, proto, dstPort, dstAddress, hostAddress, currentTime, unix, len);
                    }

                }
                else
                {
                    // Insert a row in the main capture panel since it's new
                    newSession(packet, proto, dstPort, dstAddress, hostAddress, currentTime, unix, len);
                }
            }
            else
            {
                // Insert a row in the main capture panel since it's new
                newSession(packet, proto, dstPort, dstAddress, hostAddress, currentTime, unix, len);
            }
        }
        catch(Exception e)
        {
        }
    }

    // Start capture
    public void startCapture() throws IOException, PcapNativeException, NotOpenException
    {
        // Make sure handle is closed if it's currently open
        if (handle != null && handle.isOpen())
        {
            handle.close();
            handle = null;

            nif = null;
            phb = null;
        }

        // Get the device by name from the combo item
        nif = Pcaps.getDevByName(display.getDevice());

        // Create a new pcaphandle
        phb = new PcapHandle.Builder(nif.getName())
                .snaplen(65536)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(10)
                .bufferSize(1024*1024);

        handle = phb.build();

        // Set the filter for the handle if one was given
        try {
            handle.setFilter(
                    display.getFilter(),
                    BpfProgram.BpfCompileMode.OPTIMIZE
            );
        }
        catch(Exception e)
        {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run()
                {
                    JOptionPane.showMessageDialog(null, "Invalid filter");
                }
            });
        }
    }

    // Capture packets and run the collectData method
    public void capturePacket() throws NotOpenException
    {
        Packet packet = handle.getNextPacket();

        if (packet == null)
        {
            return;
        }

       collectData(packet, handle.getTimestamp());
    }
}