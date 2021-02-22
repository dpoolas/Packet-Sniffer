package packetsniffer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import packetsniffer.gui.Display;

import java.io.IOException;

// Responsible for the thread that takes care of packet capture functionality
public class CaptorRunner implements Runnable
{
    // Initialize captor that analyzes/handles packet data
    private Captor Capture;

    // Initialize thread
    private Thread thread;

    // Initialize variable for whether the thread is suspended or not
    private volatile boolean suspended = true;


    public CaptorRunner(Display display) throws IOException, PcapNativeException, NotOpenException
    {
        // Create new captor/packet capture
        Capture = new Captor(display);

        // Initialize thread
        thread = new Thread(this);

        // Start the thread
        thread.start();

        // Suspend the thread until the user clicks capture
        this.suspend();
    }

    // Suspends capturing
    public synchronized void suspend()
    {
        suspended = true;
    }

    // Gets the capture
    public Captor getCapture()
    {
        return Capture;
    }

    // Resume capturing
    public synchronized void resume()
    {
        try
        {
            Capture.startCapture();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        catch (PcapNativeException e)
        {
            e.printStackTrace();
        }
        catch (NotOpenException e)
        {
            e.printStackTrace();
        }

        suspended = false;
        notify();
    }

    // Check if the thread is currently suspended
    public synchronized boolean isSuspended()
    {
        return suspended;
    }

    @Override
    public void run()
    {
        // Infinite loop
        while(true)
        {
            // While the thread isn't suspended capture packets or run wait
            synchronized (this)
            {
                while (suspended)
                {
                    try
                    {
                        wait();
                    } catch (InterruptedException e)
                    {
                        e.printStackTrace();
                    }
                }
            }

           try
           {
               Capture.capturePacket();
           }
           catch (NotOpenException e)
           {
               e.printStackTrace();
           }
       }
    }
}
