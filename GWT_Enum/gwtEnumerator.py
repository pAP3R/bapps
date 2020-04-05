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
from gwtEnum import gwtEnum
import sys
import re


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

        # Register GUI, calls getUIComponent()
        callbacks.addSuiteTab(self)

        return 

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "GWT-RPCer"

    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return GWTEnumTab(self, controller, editable)

    # Passes the UI to burp
    def getUiComponent(self):
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", tabbedPane);

        # First tab
        parseTab = swing.JPanel(BorderLayout())
        tabbedPane.addTab("Parser", parseTab)        
        
        # Second tab
        enumTab = swing.JPanel(BorderLayout())
        tabbedPane.addTab("Enumerate Functions", enumTab)

        # Create a vertical box to house GWT message and label
        # Create a horizontal box for GWT-RPC text box's label
        # Add the label to the horizontal box
        # Add the horizontal box to the vertical box
        gwtMessageBoxVertical = swing.Box.createVerticalBox()
        gwtLabelBoxHorizontal = swing.Box.createHorizontalBox()
        gwtRPCTextLabel = swing.JLabel("GWT-RPC Message")
        gwtLabelBoxHorizontal.add(gwtRPCTextLabel)
        gwtMessageBoxVertical.add(gwtLabelBoxHorizontal)

        # Create a horizontal text box to house the GWT message itself
        # Add text area to message box
        # Add new box to gwtMessageBoxVertical
        gwtMessageTextBoxHorizontal = swing.Box.createHorizontalBox()
        self.gwtTextArea = swing.JTextArea('', 4, 120)
        self.gwtTextArea.setLineWrap(True)
        gwtMessageTextBoxHorizontal.add(self.gwtTextArea)
        gwtMessageBoxVertical.add(gwtMessageTextBoxHorizontal)

        #
        gwtParseButtonBoxHorizontal = swing.Box.createHorizontalBox()    
        parseButtonPanel = swing.JPanel()
        parseButtonPanel.add(swing.JButton('Parse', actionPerformed=self.parseGWT))
        gwtParseButtonBoxHorizontal.add(parseButtonPanel)
        gwtMessageBoxVertical.add(gwtParseButtonBoxHorizontal)

        # Panel for the boxes. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box

        parseTabGWTMessageBoxHorizontal = swing.Box.createHorizontalBox()
        parseTabGWTMessageBoxHorizontal.add(gwtMessageBoxVertical)
        parseTab.add("North", parseTabGWTMessageBoxHorizontal)

        parsedBoxVertical = swing.Box.createVerticalBox()

        parsedBoxHorizontal = swing.Box.createHorizontalBox()
        self.parsedGWTField = swing.JTextArea()
        parsedBoxHorizontal.add(self.parsedGWTField)
        parsedBoxVertical.add(parsedBoxHorizontal)

        # Label for the insertion points box
        # horizontal box (label)
        # horizontal box (textarea)
        # inside a vertical box (insertBoxVertical)
        insertBoxVertical = swing.Box.createVerticalBox()

        insertPointBoxHorizontal = swing.Box.createHorizontalBox()
        self.insertPointField = swing.JTextArea()
        insertPointBoxHorizontal.add(self.insertPointField)
        insertBoxVertical.add(insertPointBoxHorizontal)

        functions = ["test", "test2"]
        functionList = swing.JList(functions)


        # Create and set split pane contents for enumerate tab
        spl = swing.JSplitPane(swing.JSplitPane.HORIZONTAL_SPLIT)
        spl.leftComponent = swing.JScrollPane(functionList)
        spl.rightComponent = swing.JLabel("right")

        enumTab.add("Center", spl)
      
        parseTabTabbedPane = swing.JTabbedPane()
        parseTab.add(parseTabTabbedPane);

        # Parse tab
        parsedRPCTab = swing.JPanel(BorderLayout())
        parseTabTabbedPane.addTab("Parsed", parsedRPCTab)        
        
        # Insert points tab
        insertPointsTab = swing.JPanel(BorderLayout())
        parseTabTabbedPane.addTab("Insertion Points", insertPointsTab)

        parsedRPCTab.add("Center", parsedBoxVertical)
        insertPointsTab.add("Center", insertBoxVertical)

        return self.tab

    # Create the context menu for sending GWT-RPC bodies to the enum tab
    #
    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()

        # Check context of the menu invocation-- populate appropriately
        # 0 = CONTEXT_MESSAGE_EDITOR_REQUEST
        # 1 = CONTEXT_MESSAGE_EDITOR_RESPONSE
        # 2 = CONTEXT_MESSAGE_VIEWER_REQUEST
        # 3 = CONTEXT_MESSAGE_VIEWER_RESPONSE
        # 4 = CONTEXT_TARGET_SITE_MAP_TREE
        # etc. 
        # https://portswigger.net/burp/extender/api/burp/IContextMenuInvocation.html

        menuContext = invocation.getInvocationContext()

        # Check if GWT present
        # Get IHTTPRequestResponse object , run getRequest against it to create IRequestInfo object
        # IHttpRequestResponse[] getSelectedMessages();
        msg = self.context.getSelectedMessages()[0].getRequest()

        # Analyze the IRequestInfo object and create a temp value to grab the body contents
        r_temp = self._helpers.analyzeRequest(msg)
        message = msg[r_temp.getBodyOffset():].tostring()
        # Match on 1|1|1|blah|
        match = re.match("^\d\|\d\|\d\|.*\|", message)

        # Return appropriate menu items
        if match:
            if menuContext == 3 or menuContext == 4 or menuContext == 6:
                enumGWTMenuItem = JMenuItem("GWT-RPCer - Enumerate supported GWT-RPC functions", actionPerformed=self.enumGWTFunctions)
                menuList.add(enumGWTMenuItem)
                return menuList 
            if menuContext == 0 or menuContext == 2:
                parseGWTMenuItem = JMenuItem("GWT-RPCer - Parse GWT-RPC body", actionPerformed=self.parseGWTBody)
                menuList.add(parseGWTMenuItem)
                return menuList 
        else:
            return menuList        


    # Call the GWT Parser to parse the GWT, duh
    #
    def parseGWT(self, event):

        gwt = GWTParser()
        gwt.burp

        gwt_Deser = gwt.deserialize(self.gwtTextArea.text)
        value = gwt.display()
        
        self.parsedGWTField.text = str(value)
        self.insertPointField.text = gwt.get_fuzzstr()
    

    # Called on context menu click
    # 
    def parseGWTBody(self, event):
        
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

        # Write the GWT-RPC request to the text area
        for value in message:
            self.gwtTextArea.append(value)

        # Call parseGWT when sent via Context-Menu
        try: 
            gwt = GWTParser()
            gwt.burp
    
            gwt_Deser = gwt.deserialize(self.gwtTextArea.text)
            value = gwt.display()
            
            self.parsedGWTField.text = str(value)
            self.insertPointField.text = gwt.get_fuzzstr()

        except Exception as er:
            # Print whatever exception occurred if the body was not parsed properly
            print("[!] Exception occurred, is the body a valid GWT-RPC?\nException:")
            print(er)
        
    # Placeholder function for the GWT enumerator
    #
    def enumGWTFunctions(self, event):
        # This will always be a response
        # I think...

        # Get IHTTPRequestResponse object , run getRequest against it to create IRequestInfo object
        # IHttpRequestResponse[] getSelectedMessages();
        print("test")

        msg = self.context.getSelectedMessages()[0].getResponse()
        print("test")
        print type(msg)
        # Analyze the IRequestInfo object and create a temp value to grab the body contents
        r_temp = self._helpers.analyzeRequest(msg)
        print type(r_temp)
        message = msg[r_temp.getBodyOffset():].tostring()
        print(message)

        gwt = gwtEnum()
        gwt.gwtEnum(message)

        print("It works!")
        pass



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
        return "Parsed GWT"
        
    def getUiComponent(self):
        return self._gwtMessageTabInput.getComponent()
        

        
    def isEnabled(self, content, isRequest):
        # enable this tab for requests containing GWT values in the request body

        r = self._helpers.analyzeRequest(content)

        msg = content[r.getBodyOffset():].tostring()
        # Match on 1|1|1|blah|
        match = re.match("^\d\|\d\|\d\|.*\|", msg)
        if match:
            return True
        else:
            return False
        
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


