package packetsniffer;

import packetsniffer.database.DatabaseCallback;
import packetsniffer.database.DatabaseConnection;
import packetsniffer.gui.Display;
import packetsniffer.utils.IPUtilities;
import packetsniffer.utils.SubnetUtils;

import javax.swing.*;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;

public class Watchlists
{
    // Initialize NavigableMap for subnets in the blacklist
    private NavigableMap<Long, Long> blackSubnets;

    // Initialize Map for ips in the blacklist
    private Map<Long, Boolean> blackIPs;

    // Initialize NavigableMap for subnets in the whitelist
    private NavigableMap<Long, Long> whiteSubnets;

    // Initialize map for ips in the whitelist
    private Map<Long, Boolean> whiteIPs;

    // Initialize utils to convert subnet in cidr notation to a lower/higher ip range (Example: 192.168.1.1 - 192.168.1.100)
    private SubnetUtils utils;
    private Display display;

    // Check if an ip is valid (For validity checking for the blacklist and whitelist)
    private String ipPattern = "^((0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)\\.){3}(0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)$";;

    // Check if the ip being entered in the blacklist or whitelist is a valid ip
    private boolean validIP(final String ip)
    {
        return ip.matches(ipPattern);
    }

    // Check if an ip is in the blaclist
    public boolean inBlacklist(String ip)
    {
        try
        {
            // Convert the ip to a long with how it's stored in the navigable map
            long ipRes = IPUtilities.ipToLong(ip);

            // if the HashMap contains the ip then it's in the blacklist
            if (blackIPs.containsKey(ipRes))
            {
                return true;
            }

            // Get the lowest key that's close to the ip given
            long lower = blackSubnets.floorKey(ipRes);

            // Get the value for the lowest value in the range that's closest to the ip
            long higher = blackSubnets.get(lower);

            // If the ip is more than the lowest key and is less than the end of the range in the subnet it's in the blacklist
            if (lower < ipRes && ipRes < higher)
            {
                return true;
            }
        }
        catch (Exception e)
        {

        }

        return false;
    }

    public boolean inWhitelist(String ip)
    {
        try
        {
            // Convert the ip to a long with how it's stored in the navigable map
            long ipRes = IPUtilities.ipToLong(ip);

            // if the HashMap contains the ip then it's in the whitelist
            if (whiteIPs.containsKey(ipRes))
            {
                return true;
            }

            // Get the lowest key that's close to the ip given
            long lower = whiteSubnets.floorKey(ipRes);

            // Get the value for the lowest value in the range that's closest to the ip
            long higher = whiteSubnets.get(lower);

            // If the ip is more than the lowest key and is less than the end of the range in the subnet it's in the whitelist
            if (lower < ipRes && ipRes < higher)
            {
                return true;
            }
        }
        catch (Exception e)
        {

        }

        return false;
    }

    // Add to blacklist
    public void addBlacklist(String ips)
    {
        try
        {
            // Try to see if the ip is a subnet/in cidr notation
            utils = new SubnetUtils(ips);

            // Get the info
            SubnetUtils.SubnetInfo info = utils.getInfo();

            // Get the lowest address in the subnet range
            long start = IPUtilities.ipToLong(info.getLowAddress());

            // Get the highest address in the subnet range
            long end = IPUtilities.ipToLong(info.getHighAddress());

            // Put the start and end in the Navigable map (Key = lowest | Value = Highest)
            blackSubnets.put(start, end);

            // Put the subnet in the blacklist in the database
            DatabaseConnection.QueryNoValue("REPLACE INTO watchlist (ip, type) Values('" + ips + "', " + "0" + ")");

            // Commit to database
            DatabaseConnection.commit();

            // Add to watch for that ip/put ip in blacklist in the EDT/gui thread
            SwingUtilities.invokeLater(new Runnable()
            {
                @Override
                public void run()
                {
                    display.addWatch(ips);
                }
            });
        }
        catch (Exception e)
        {
            // If the IP is valid and it's not a subnet
            if (validIP(ips))
            {
                // Convert the IP to a long
                long ipres = IPUtilities.ipToLong(ips);

                // Put the ip in the HashMap
                blackIPs.put(ipres, true);

                // Put the ip in the blacklist in the database
                try
                {
                    DatabaseConnection.QueryNoValue("REPLACE INTO watchlist (ip, type) Values('" + ips + "', " + "0" + ")");

                    // Commit to database
                    DatabaseConnection.commit();
                }
                catch (SQLException e1)
                {
                    e1.printStackTrace();
                }

                // Add to blacklist on the EDT/gui thread
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run()
                    {
                        display.addWatch(ips);
                    }
                });
            }
            else
            {
                // Display error if it's not a valid IP
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run()
                    {
                        JOptionPane.showMessageDialog(null, "That is not a valid IP.");
                    }
                });
            }
        }
    }

    // Remove from blacklist
    public void removeBlacklist(String ips)
    {
        // Delete from the blacklist in the database
        try
        {
            DatabaseConnection.QueryNoValue("DELETE from watchlist where ip = '" + ips + "' and type=0");
        }
        catch (SQLException e)
        {
            e.printStackTrace();
        }


        try
        {

            // See if the given IP/subnet is in cidr notation
            utils = new SubnetUtils(ips);

            SubnetUtils.SubnetInfo info = utils.getInfo();

            long start = IPUtilities.ipToLong(info.getLowAddress());

            // Remove the start value from the blacklist subnet navigable map
            blackSubnets.remove(start);
        }
        catch (Exception e)
        {
            // Convert the ip to a long
            long ipres = IPUtilities.ipToLong(ips);

            // Remove it from the blacklist hashmap
            blackIPs.remove(ipres);
        }
    }

    // Add to whitelist
    public void addWhitelist(String ips)
    {
        try
        {

            // Try to see if the ip is a subnet/in cidr notation
            utils = new SubnetUtils(ips);

            // Get the info
            SubnetUtils.SubnetInfo info = utils.getInfo();

            // Get the lowest address in the subnet range
            long start = IPUtilities.ipToLong(info.getLowAddress());

            // Get the highest address in the subnet range
            long end = IPUtilities.ipToLong(info.getHighAddress());

            // Put the start and end in the Navigable map (Key = lowest | Value = Highest)
            whiteSubnets.put(start, end);

            // Put the subnet in the whitelist in the database
            DatabaseConnection.QueryNoValue("REPLACE INTO watchlist (ip, type) Values('" + ips + "', " + "1" + ")");

            // Commit to database
            DatabaseConnection.commit();

            // Add to whitelist for that ip/subnet | Put ip in whitelist in the EDT/gui thread
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run()
                {
                    display.addWhitelist(ips);
                }
            });
        }
        catch (Exception e)
        {
            // If the IP is valid and it's not a subnet
            if (validIP(ips))
            {
                // Convert the IP to a long
                long ipres = IPUtilities.ipToLong(ips);

                // Put the ip in the HashMap
                whiteIPs.put(ipres, true);

                // Put the ip in the whitelist in the database
                try
                {
                    DatabaseConnection.QueryNoValue("REPLACE INTO watchlist (ip, type) Values('" + ips + "', " + "1" + ")");

                    // Commit to database
                    DatabaseConnection.commit();
                }
                catch (SQLException e1)
                {
                    e1.printStackTrace();
                }


                // Add to whitelist on the EDT/gui thread
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run()
                    {
                        display.addWhitelist(ips);
                    }
                });
            }
            else
            {

                // Display error if it's not a valid IP
                SwingUtilities.invokeLater(new Runnable()
                {
                    @Override
                    public void run()
                    {
                        JOptionPane.showMessageDialog(null, "That is not a valid IP.");
                    }
                });
            }
        }
    }

    // Remove from whitelist
    public void removeWhitelist(String ips)
    {
        // Delete from the whitelist in the database
        try
        {
            DatabaseConnection.QueryNoValue("DELETE from watchlist where ip = '" + ips + "' and type=1");
        }
        catch (SQLException e)
        {
            e.printStackTrace();
        }

        try
        {

            // See if the given IP/subnet is in cidr notation
            utils = new SubnetUtils(ips);

            SubnetUtils.SubnetInfo info = utils.getInfo();

            long start = IPUtilities.ipToLong(info.getLowAddress());

            // Remove the start value from the whitelist subnet navigable map
            whiteSubnets.remove(start);
        }
        catch (Exception e)
        {

            // Convret the ip to a long
            long ipres = IPUtilities.ipToLong(ips);

            // Remove it from the whitelist hashmap
            whiteIPs.remove(ipres);
        }
    }

    // Constructor
    public Watchlists(Display display)
    {

        // Get display
        this.display = display;

        // Initialize new TreeMap with a key value of two longs for blacklisted subnets (Start - End)
        blackSubnets = new TreeMap<Long, Long>();

        // Initialize new HashMap for individual blacklisted IPs (IP - Boolean)
        blackIPs = new HashMap<Long, Boolean>();


        // Initialize new TreeMap with a key value of two longs for whitelisted subnets (Start - End)
        whiteSubnets = new TreeMap<Long, Long>();

        // Initialize new HashMap for individual whitelisted IPs (IP - Boolean)
        whiteIPs = new HashMap<Long, Boolean>();

        // Get the current blacklisted/whitelisted IPs/Subnets
        try
        {
            DatabaseConnection.QueryCallback("SELECT * from watchlist;", new DatabaseCallback() {
                @Override
                public void callbackMethod(ResultSet rs) throws SQLException
                {

                    // Get all the results
                    while (rs.next())
                    {
                        String ip = rs.getString(1);
                        int type = rs.getInt(2);

                        // If the type for the IP is zero then it's for the blacklist
                        if (type == 0)
                        {

                            // Add to blacklist on the EDT/gui thread
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    display.addWatch(ip);
                                }
                            });

                            try
                            {
                                // See if the given IP/subnet is in cidr notation
                                utils = new SubnetUtils(ip);

                                SubnetUtils.SubnetInfo info = utils.getInfo();


                                // Get the start and end value
                                long start = IPUtilities.ipToLong(info.getLowAddress());
                                long end = IPUtilities.ipToLong(info.getHighAddress());

                                // Put the start and end value for the subnet in the blacklist navigable map
                                blackSubnets.put(start, end);


                            }
                            catch (Exception e)
                            {
                                // Convert the IP to a long
                                long ipres = IPUtilities.ipToLong(ip);

                                // Remove it from the blacklist hashmap
                                blackIPs.put(ipres, true);
                                continue;
                            }
                        }
                        else
                        {
                            // It's in the whitelist if the type isn't zero.

                            // Add the IP/subnet to the whitelist on the EDT/gui thread
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    display.addWhitelist(ip);
                                }
                            });


                            try
                            {

                                //See if the given IP/subnet is in cidr notation
                                utils = new SubnetUtils(ip);

                                SubnetUtils.SubnetInfo info = utils.getInfo();

                                // Get the start and end value for the subnet in the whitelist
                                long start = IPUtilities.ipToLong(info.getLowAddress());
                                long end = IPUtilities.ipToLong(info.getHighAddress());


                                // Put the start and end value for the subnet in the whitelist
                                whiteSubnets.put(start, end);


                            }
                            catch (Exception e)
                            {
                                // Convert the IP to a long
                                long ipres = IPUtilities.ipToLong(ip);

                                // Put the IP in the whitelist hashmap
                                whiteIPs.put(ipres, true);
                                continue;
                            }
                        }
                    }
                }
            });

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
