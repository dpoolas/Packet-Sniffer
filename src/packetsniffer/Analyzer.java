package packetsniffer;

import packetsniffer.database.DatabaseConnection;
import packetsniffer.gui.Display;

import javax.swing.*;
import java.io.IOException;
import java.net.ServerSocket;
import java.sql.SQLException;

public class Analyzer
{

    public static void main (String[] args) throws IOException
    {
        // Create a socket on port 26732 (Used to check if the program is currently running.)
        ServerSocket ss;

        try
        {
            ss = new ServerSocket(26732);
        }
        catch (IOException e)
        {
            JOptionPane.showMessageDialog(null,
                    "This application is currently already running.",
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            System.exit(-1);
        }

        // Invoke the gui on the EDT thread (Make sure gui is running on its own thread to separate it from background tasks.
        new Thread(new Runnable()
        {
            public void run()
            {
                SwingUtilities.invokeLater(() ->
                {
                    Display display = new Display();
                });
            }
        }).start();

        // Initialize the database connection.
        DatabaseConnection.init();


        // Delete the sessions in the database that have a last seen that is older than 24 hours.
        try
        {
            DatabaseConnection.QueryNoValue("DELETE FROM sessions WHERE (lastseen < (strftime('%s', 'now') - 86400));");
        }
        catch (SQLException e)
        {
            e.printStackTrace();
        }

        // Make sure to commit to the database when shutting down the program.
        Runtime.getRuntime().addShutdownHook(new Thread()
        {
            @Override
            public void run()
            {
                DatabaseConnection.commit();
            }
        });
    }

}