package packetsniffer.gui;

/***********************
 Class for displaying a certain value (For network adapter/interface selection)
 ***********************/
class ComboItem
{
    private String display;
    private String realValue;

    public ComboItem(String display, String realValue)
    {
        this.display = display;
        this.realValue = realValue;
    }

    public String getDescription()
    {

        return realValue;
    }

    public String toString()
    {

        return display;
    }
}