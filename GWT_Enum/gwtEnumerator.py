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
        callbacks.setExtensionName("GWT Enumerator")
        
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
        textLabel = swing.JLabel("GWT Message")
        boxHorizontal.add(textLabel)
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
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("Parse", firstTab)

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
        boxHorizontal.add(swing.JLabel("  Parsed GWT    :"))
        boxHorizontal.add(self.parsedGWTField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.insertPointField = swing.JTextArea()
        boxHorizontal.add(swing.JLabel("  Insertion Points:"))
        boxHorizontal.add(self.insertPointField)
        boxVertical.add(boxHorizontal)

        firstTab.add(boxVertical, "Center")

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
        return "GWT Enumerator"

    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return GWTEnumTab(self, controller, editable)

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab


    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Send selected text to GWT Enumerator", actionPerformed=self.sendtoGWT)
        menuList.add(menuItem)
        return menuList


    def sendtoGWT(self, event):
        pass
        '''
        messages = self.context.getSelectedMessages()
        print(type(messages))
        print(dir(messages))
        print(messages.tostring())
        values = []

        r = self._helpers.analyzeRequest(messages[0])
        print(r)

        for value in messages:
            values.append(str(value))
        print(values)

        for value in values:
            self.gwtTextArea.append(value)
        '''


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
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        
    #
    # implement IMessageEditorTab
    #

    def getTabCaption(self):
        return "GWT Enum"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing a data parameter
        return isRequest and True
        #return isRequest and not self._extender._helpers.getRequestParameter(content, "data") is None
        
    def setMessage(self, content, isRequest):

        # Instantiate GWTParser
        gwt = GWTParser()

        if content is None:
            # clear our display
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        
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

            #self._txtInput.setText(self._helpers.stringToBytes(value))
            self._txtInput.setText(msg)
            self._txtInput.setEditable(self._editable)

        self._currentMessage = content
        
        
    def getMessage(self):    

        # determine whether the user modified the deserialized data
        if self._txtInput.isTextModified():
            # Get text of message 
            data = self._helpers.bytesToString(self._txtInput.getText())
            #print("Text: " + data)

            # Get full request and return with the changed data
            r = self._helpers.analyzeRequest(self._currentMessage)
            return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
            
        # Return normal messgae if no modification
        return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        return self._txtInput.getSelectedText()


