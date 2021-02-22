package packetsniffer.gui;

import packetsniffer.CaptorRunner;
import packetsniffer.database.DatabaseConnection;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class CaptureButton extends JButton
{
    // Initialize reference variable to capture runner
    private CaptorRunner runner;

    CaptureButton(String text, Display display)
    {
        super(text);

        // Get runner from display
        this.runner = display.getRunner();

        // Action handles whether or not to run/suspend the capture program
        this.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                if (runner.isSuspended())
                {
                    runner.resume();
                    setText("Stop");
                }
                else
                {
                    runner.suspend();
                    setText("Capture");

                    // Do commit because capture stopped
                    DatabaseConnection.commit();
                }
            }
        });
    }
}
