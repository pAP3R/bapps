# GWT Enumerator / Parser

This is a bapp for assisting testing of GWT RPC requests. It combines aspects of the GWT Penetration Testing Toolset into burp, allowing for more effective GWT-RPC request editing via repeater. The extension will allow for automatic insertion point identification and enumeration of available GWT-RPC requests. 

## Example:
Take the following GWT-RPC request:

	5|0|7|http://localhost:8080/testproject/|29F4EA1240F157649C12466F01F46F60|com.test.client.GreetingService|greetServer|java.lang.String|myInput1|myInput2|1|2|3|4|2|5|5|6|7|

Deserialized:

	Serialized Object:
	5|0|7|http://localhost:8080/testproject/|29F4EA1240F157649C12466F01F46F60|com.test.client.GreetingService|greetServer|java.lang.String|myInput1|myInput2|1|2|3|4|2|5|5|6|7|
	
	Stream Version:	5
	         Flags:	0
	Column Numbers:	7
	          Host:	http://localhost:8080/testproject/
	          Hash:	29F4EA1240F157649C12466F01F46F60
	    Class Name:	com.test.client.GreetingService
	        Method:	greetServer
	   # of Params:	2
	
	    Parameters:
	{'flag': False,
	 'is_array': False,
	 'is_custom_obj': False,
	 'is_list': False,
	 'typename': 'java.lang.String',
	 'values': ['myInput1']}
	{'flag': False,
	 'is_array': False,
	 'is_custom_obj': False,
	 'is_list': False,
	 'typename': 'java.lang.String',
	 'values': ['myInput2']}


## Install / Usage:

1. Add gwtEnumerator.py to Burp extensions
	That's it
	Buncha extra garbage that I'll clean up later

Parsing GWT-RPC requests

	1. Right click request with a GWT body and send it to the parser
	2. In the GWT-RPCer tab, the parser tab should be prepopulated with the serialized object, deserialized object and insertion points (if any) added

Scanning GWT-RPC

	1. Send the request to the parser or paste the GWT body into it
	2. Select the 'Insertion points' tab and copy the output
	3. Send the full request to intruder, replace the GWT payload with the parser's output
	4. Scan manual insertion points

	No ETA on scanner integration




## Current Features:

- Custom HTTP message tab 
- GUI tab
	+ Message parser
	+ Insertion point auto-do-er

## Features Planned:

- Split custom tab to GWT up top, bottom half deserialized
- DONE - Identify fuzz points
- WIP - Add full tab for enum (like wsdler)
- DONE - Context menu options (Send selected text / request, etc)
- Error handling
	Handle parse failures, etc
- DONE - GWT-RPC detection
	WIP - Varying versions
- Scanner integration



GWT Toolset:
	https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset/blob/master/gwtparse/gwtparse.py

