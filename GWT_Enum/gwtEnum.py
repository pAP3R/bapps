# GWT-RPC Parser, standalone
# Credit: Ron Gutierrez https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset/
#
# standalone version of the GWT enum script for burp integration
#
#
import re
import pprint

class gwtEnum():

    def gwtEnum(self, response):
    
        for line in response:
        
            # Service and Method name Enumeration
            rpc_method_match = re.match( "^function \w+\(.*method\:([A-Za-z0-9_\$]+),.*$", line )
            
            if rpc_method_match:
                if rpc_method_match.group(1) == "a":
                    continue
                  
                rpc_js_function = rpc_method_match.group(0).split(';')
                service_and_method = ""
                
                method_name = get_global_val( rpc_method_match.group(1), response )
                if method_name is None:
                    continue
                    
                methods.append(  "%s( " % method_name.replace( '_Proxy.', '.' ) )
                
                # Parameter Enumeration
                for i in range(0, len(rpc_js_function)):
                    try_match = re.match( "^try{.*$", rpc_js_function[i] )
                    if try_match:
                        i += 1
                        func_match = re.match( "^([A-Za-z0-9_\$]+)\(.*", rpc_js_function[i] )
                        payload_function = ""
                        if func_match:
                            payload_function = func_match.group(1)
                        
                        i += 1
                        param_match = re.match( "^"+re.escape(payload_function)+
                            "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)", 
                            rpc_js_function[i] )
                            
                        num_of_params = 0
                        if param_match:
                            num_of_params = int(get_global_val( param_match.group(1), response ))
                        
                        for j in range( 0, num_of_params ):
                            i += 1
                            
                            param_var_match = re.match( "^"+re.escape(payload_function)+
                                "\([A-Za-z0-9_\$]+\.[A-Za-z0-9_\$]+,[A-Za-z0-9_\$]+\+"
                                "[A-Za-z0-9_\$]+\([A-Za-z0-9_\$]+,([A-Za-z0-9_\$]+)\)\)$", 
                                rpc_js_function[i] )
                                
                            if param_var_match:
                                param = get_global_val( param_var_match.group(1), response )
                                methods[-1] = methods[-1]+param+","
                             
                        a_method = methods[-1][:-1]
                        methods[-1] = a_method + " )"
                        break
    
        line_decor = "\n===========================\n"
        print( "\n%sEnumerated Methods%s" % ( line_decor, line_decor ) )
        methods_sorted = sorted(list(set(methods))) #uniq
        
        for method in methods_sorted:
            print( method )