from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from GWTParser import GWTParser
from exceptions_fix import FixBurpExceptions
import sys


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    
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
        
    # 
    # implement IMessageEditorTabFactory
    #
    
    def createNewInstance(self, controller, editable):
        # create a new instance of our custom editor tab
        return GWTEnumTab(self, controller, editable)
        

FixBurpExceptions()

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


