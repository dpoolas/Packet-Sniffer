package packetsniffer.database;

import java.sql.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DatabaseConnection
{
    // Static connection for the sqlite database
    private static Connection connection;

    // Single thread pool that queries will be run on
    private static ExecutorService pool = Executors.newSingleThreadExecutor();

    public static final void init()
    {
        // Connect to the database (info.db)
        pool.execute(new Runnable()
        {
            @Override
            public void run()
            {
                try

                {
                    connection = DriverManager.getConnection("jdbc:sqlite:info.db");
                    connection.setAutoCommit(false);
                    System.out.println("Connected to sqlite database info.db!");
                } catch (SQLException e)

                {
                    System.out.println("Failed to get connection.");
                }
            }
        });
    }

    // Return result set/table from SQL Query
    public static void QueryCallback(String query, DatabaseCallback callback)
    {

        //  Execute a query and handle the resultset in an asynchronous callback
        pool.execute(new Runnable()
        {
            @Override
            public void run()
            {
                ResultSet rs;
                Statement st = null;

                // Create the statement, execute the query, and run the callback method/function.
                try
                {
                    st = connection.createStatement();
                    rs = st.executeQuery(query);

                    callback.callbackMethod(rs);

                    st.close();
                    rs.close();
                }
                catch (SQLException e)
                {
                    e.printStackTrace();
                }
            }
        });
    }

    // Execute a SQL query (Asynchronous)
    public static void QueryNoValue(String query) throws SQLException
    {
        pool.execute(new Runnable()
        {
            @Override
            public void run()
            {
                Statement st = null;
                try
                {
                    st = connection.createStatement();
                    st.executeUpdate(query);

                    st.close();
                }
                catch (SQLException e)
                {
                    e.printStackTrace();
                }
            }
        });
    }

    // Execute a SQL query (Wait for query to be executed)
    public static void QueryNoValueWait(String query) throws SQLException
    {
        Statement st = null;
        try
        {
            st = connection.createStatement();
            st.executeUpdate(query);
            st.close();
        }
        catch(SQLException e)
        {
            e.printStackTrace();
        }
    }

    // Auto commit is off so commit is required after capture, adding/removing from blacklist/whitelist, etc.
    public static void commit()
    {
        pool.execute(new Runnable()
        {
            @Override
            public void run()
            {
                try
                {
                    connection.commit();
                }
                catch (SQLException e)
                {
                    e.printStackTrace();
                }
            }
        });
    }
}
