package packetsniffer.gui;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/*************************
Handles whether an item is in the blacklist/display functionality for blacklist.

Also handles formatting for bandwidth and dates to display them in appropriate formats
*************************/
class CustomRenderer extends DefaultTableCellRenderer
{
    // Initialize HashMap for rows that are in the blacklist
    private Map warning = new HashMap<Integer, Boolean>();

    // Date format for how dates should be show in tables
    SimpleDateFormat doDate = new SimpleDateFormat("hh:mm:ss a");

    // Put a row into the blacklist
    public void addWarning(int row)
    {
        warning.put(row, true);
    }

    // Remove a row from the blacklist
    public void removeWarning(int row)
    {
        warning.remove(row);
    }

    // Formatting the bandwidth (Initial value is in bytes)
    private String getBandwidth(float bandwidth)
    {
        // Checks if the amount is 125000 bytes or at least 1 megabit per second
        if (bandwidth > 125000)
        {
            String mbps = String.format("%.5f", bandwidth * .000008);

            return  mbps + " Mbps";
        }
        else
        {
            // Checks if the bandwidth is at least 4 bytes
            if (bandwidth >= 4)
            {
                String kbps = String.format("%.5f", bandwidth * .008);

                return kbps + " Kbps";
            }
            else
            {

                // If it's really small it'll just show the value in bytes per second
                return bandwidth + " bps";
            }
        }
    }

    // Rendering the table components
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
    {

        // If the value is a date type
        if (value instanceof Date)
        {
            // Format the date
            value = doDate.format(value);
        }

        // If the table column is for bandwidth
        if (table.getColumnName(column) == "Bandwidth")
        {
            // Format the bandwidth
            value = getBandwidth((float)value);
        }

        Component cellComponent = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        // If the table is sorted, it will lose the row count so convert the row index to how the model is currently sorted
        int realRow = table.convertRowIndexToModel(row);

        // If the row is selected make the background light gray
        if (isSelected)
        {
            cellComponent.setBackground(Color.LIGHT_GRAY);
            cellComponent.setForeground(Color.BLACK);
        }
        else
        {
            // If the blacklist contains the row then make the background red and text white
            if (warning.containsKey(realRow))
            {
                cellComponent.setBackground(Color.RED);
                cellComponent.setForeground(Color.WHITE);
            }
            else
            {
                // Normal rendering - Black text and white background
                cellComponent.setBackground(Color.WHITE);
                cellComponent.setForeground(Color.BLACK);
            }
        }

        return cellComponent;
    }


}