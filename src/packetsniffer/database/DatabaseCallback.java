package packetsniffer.database;

import java.sql.ResultSet;
import java.sql.SQLException;

// Allows for callback methods to be ran after SQLite queries
public interface DatabaseCallback
{
    public void callbackMethod(ResultSet rs) throws SQLException;
}