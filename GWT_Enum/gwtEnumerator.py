from burp import IBurpExtender, ITab, IContextMenuFactory
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from GWTParser import GWTParser
from exceptions_fix import FixBurpExceptions
from javax import swing
from javax.swing import JMenuItem
from java.util import ArrayList
from java.awt import BorderLayout
import sys


class BurpExtender(IBurpExtender, ITab, IMessageEditorTabFactory, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):

        sys.stdout = callbacks.getStdout()

        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("GWT-RPC Enumerator")
        
        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        # Register for context menu use
        callbacks.registerContextMenuFactory(self)

        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Tab options / layout

        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        
        # Create the label for the text area
        # GWT Message Tab
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        gwtRPCTextLabel = swing.JLabel("GWT-RPC Message")
        boxHorizontal.add(gwtRPCTextLabel)
        boxVertical.add(boxHorizontal)

        # Create the text area itself
        boxHorizontal = swing.Box.createHorizontalBox()
        self.gwtTextArea = swing.JTextArea('', 4, 120)
        self.gwtTextArea.setLineWrap(True)
        boxHorizontal.add(self.gwtTextArea)
        boxVertical.add(boxHorizontal)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH) 

        # Button for first tab
        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Parse', actionPerformed=self.parseGWT))
        textPanel.add(buttonPanel)

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", tabbedPane);

        # First tab
        parseTab = swing.JPanel()
        parseTab.layout = BorderLayout()
        tabbedPane.addTab("Parse", parseTab)

        '''
        # Second tab
        secondTab = swing.JPanel()
        secondTab.layout = BorderLayout()
        tabbedPane.addTab("Insertion Points", secondTab)
        '''

        # Panel for the boxes. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box
        parsePanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        
        boxHorizontal = swing.Box.createHorizontalBox()
        self.parsedGWTField = swing.JTextArea()
        boxHorizontal.add(swing.JLabel("  Parsed GWT-RPC:"))
        boxHorizontal.add(self.parsedGWTField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.insertPointField = swing.JTextArea()
        boxHorizontal.add(swing.JLabel("  Insertion Points:"))
        boxHorizontal.add(self.insertPointField)
        boxVertical.add(boxHorizontal)

        parseTab.add(boxVertical, "Center")

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return
        

    def parseGWT(self, event):

        gwt = GWTParser()
        gwt.burp

        gwt_Deser = gwt.deserialize(self.gwtTextArea.text)
        value = gwt.display()
        
        self.parsedGWTField.text = str(value)
        self.insertPointField.text = gwt.get_fuzzstr()
        

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "GWT-RPC Enumerator"

    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return GWTEnumTab(self, controller, editable)

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    # Create the context menu for sending GWT-RPC bodies to the enum tab
    #
    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send GWT-RPC body to GWT Enumerator", actionPerformed=self.sendtoGWT)
        menuList.add(menuItem)
        return menuList


    # Called on context menu click
    # 
    def sendtoGWT(self, event):
        
        # Get IHTTPRequestResponse object , run getRequest against it to create IRequestInfo object
        # IHttpRequestResponse[] getSelectedMessages();
        msg = self.context.getSelectedMessages()[0].getRequest()

        # Analyze the IRequestInfo object and create a temp value to grab the body contents
        r_temp = self._helpers.analyzeRequest(msg)
        message = msg[r_temp.getBodyOffset():].tostring()
        
        values = []

        # Clear the contents of each text area/box if they're not empty
        if len(self.gwtTextArea.text) > 1:
            self.gwtTextArea.text = ""
            self.parsedGWTField.text = ""
            self.insertPointField.text = ""

        for value in message:
            self.gwtTextArea.append(value)

        try: 
            # Call parseGWT when sent via Context-Menu
            self.parseGWT(self)
        except Exception as er:
            # Print whatever exception occurred if the body was not parsed properly
            print("[!] Exception occurred, is the body a valid GWT-RPC?\nException:")
            print(er)
        


#FixBurpExceptions()

# 
# class implementing IMessageEditorTab
#

class GWTEnumTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._editable = editable
        self._helpers = extender._helpers
        
        # create an instance of Burp's text editor, to display our deserialized data
        self._gwtMessageTabInput = extender._callbacks.createTextEditor()
        self._gwtMessageTabInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "GWT Enum"
        
    def getUiComponent(self):
        return self._gwtMessageTabInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return isRequest and True
        #return isRequest and not self._extender._helpers.getRequestParameter(content, "data") is None
        
    def setMessage(self, content, isRequest):

        # Instantiate GWTParser
        gwt = GWTParser()

        if content is None:
            # clear our display
            self._gwtMessageTabInput.setText(None)
            self._gwtMessageTabInput.setEditable(False)
        
        else:

            if isRequest:
                r = self._helpers.analyzeRequest(content)
            else:
                r = self._extender._helpers.analyzeResponse(content)

            # Get body contents
            msg = content[r.getBodyOffset():].tostring()
            print(msg)

            text = gwt.deserialize(msg)
            print(text)
            value = gwt.display()

            print(value)

            #self._gwtMessageTabInput.setText(self._helpers.stringToBytes(value))
            self._gwtMessageTabInput.setText(msg)
            self._gwtMessageTabInput.setEditable(self._editable)

        self._currentMessage = content
        
        
    def getMessage(self):    

        # determine whether the user modified the deserialized data
        if self._gwtMessageTabInput.isTextModified():
            # Get text of message 
            data = self._helpers.bytesToString(self._gwtMessageTabInput.getText())
            #print("Text: " + data)

            # Get full request and return with the changed data
            r = self._helpers.analyzeRequest(self._currentMessage)
            return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
            
        # Return normal messgae if no modification
        return self._currentMessage
    
    def isModified(self):
        return self._gwtMessageTabInput.isTextModified()
    
    def getSelectedData(self):
        return self._gwtMessageTabInput.getSelectedText()


