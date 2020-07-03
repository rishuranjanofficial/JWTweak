#JWTweak-v1.6

import os
import jwt
import re
import base64
import math
import json
from Cryptodome.Signature import PKCS1_v1_5, DSS, pss
from Cryptodome.Hash import SHA256, SHA384, SHA512
from Cryptodome.PublicKey import RSA, ECC

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def RSAKeypairGen():
    new_key = RSA.generate(2048, e=65537)
    pubKey = new_key.publickey().exportKey("PEM")
    privKey = new_key.exportKey("PEM")
    return pubKey,privKey  

def jwtWeak():
    """ Automate the progress of changing the algorithm of input JWT Token and then generate the new JWT based on changed algorithm """
    print("Enter the JWT Token:")
    in_jwt = input()

    if re.match(r'^ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',in_jwt):
        print(f"{bcolors.OKGREEN}\nThis is a valid input JWT Token{bcolors.ENDC}")
        print(f"{bcolors.BOLD}")

        choice = input("""
            *****************************MAIN MENU*****************************
            1: Detect the algorithm of the input JWT Token
            2: Base64 decode the input JWT Token
            3: Generate new JWT by changing the algorithm to 'none'
            4: Generate new JWT by changing the algorithm to 'HS256'
            5: Generate new JWT by changing the algorithm to 'HS384'
            6: Generate new JWT by changing the algorithm to 'HS512'
            7: Generate new JWT by changing the algorithm to 'RS256'
            8: Generate new JWT by changing the algorithm to 'RS384'
            9: Generate new JWT by changing the algorithm to 'RS512'
            10: Quit
            *******************************************************************
            Please enter your choice: """+f"{bcolors.ENDC}")
        

#######################################################################################
#Detect the algorithm of the input JWT Token
#######################################################################################

        if choice == '1':
            try:
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
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Base 64 Decode JWT
#######################################################################################

        elif choice == '2':
            try:
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
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Generate JWT Token with Algorithm type 'none'
#######################################################################################

        elif choice == '3':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
                if len(Header) % 4 != 0: #check if multiple of 4
                    while len(Header) % 4 != 0:
                        Header = Header + "="
                    req_str = base64.b64decode(Header)
                else:
                    req_str = base64.b64decode(Header)
                req_str=req_str.decode('utf-8')
                json_header = json.loads(req_str)
                algo=json_header['alg']
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
                print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

                #base64 encoded Header
                print("\nHeader="+Header)
                #base64 encoded Payload
                print("\nPayload="+Payload)
                #base64 encoded Signature
                print("\nSignature="+Signature)

                print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'none':{bcolors.ENDC}")

                json_header['alg']='none'

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
                    print("\nThe New JWT Token with Algorithm changed to 'none':\n\n"+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+b64_encoded_header+"."+b64_encoded_Payload+"."+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                elif not mod_payload:
                    print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                    json_header=str(json_header)
                    b64_Header = base64.b64encode(str_json_header.encode("utf-8"))
                    b64_encoded_header = str(b64_Header, "utf-8")

                    b64decoded_payload=str(b64decoded_payload)
                    b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                    b64_encoded_Payload = str(b64_Payload, "utf-8")
                    print("\nThe New JWT Token with Algorithm changed to 'none':\n\n"+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+b64_encoded_header+"."+b64_encoded_Payload+"."+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS256'
#######################################################################################

        elif choice == '4':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
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

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS256':\n\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

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
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS256':\n\n"+str(str_encoded_HS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS384'
#######################################################################################

        elif choice == '5':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]

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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
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
                    hs384_key=input()

                    encoded_HS384 = jwt.encode(json_mod_payload, hs384_key, algorithm='HS384')
                    str_encoded_HS384=encoded_HS384.decode('utf')

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS384':\n\n"+str(str_encoded_HS384)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

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
                    hs384_key=input()

                    encoded_HS384 = jwt.encode(json_mod_payload, hs384_key, algorithm='HS384')
                    str_encoded_HS384=encoded_HS384.decode('utf')
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS384':\n\n"+str(str_encoded_HS384)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Generate JWT Token with Algorithm type 'HS512'
#######################################################################################

        elif choice== '6':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
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
                    hs512_key=input()

                    encoded_HS512 = jwt.encode(json_mod_payload, hs512_key, algorithm='HS512')
                    str_encoded_HS512=encoded_HS512.decode('utf')

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS512':\n\n"+str(str_encoded_HS512)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

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
                    hs512_key=input()

                    encoded_HS512 = jwt.encode(json_mod_payload, hs512_key, algorithm='HS512')
                    str_encoded_HS512=encoded_HS512.decode('utf')
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'HS512':\n\n"+str(str_encoded_HS512)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except:
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")

#######################################################################################
#Generate JWT Token with Algorithm type 'RS256'
#######################################################################################

        elif choice== '7':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
                print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

                #base64 encoded Header
                print("\nHeader="+Header)
                #base64 encoded Payload
                print("\nPayload="+Payload)
                #base64 encoded Signature
                print("\nSignature="+Signature)

                print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'RS256':{bcolors.ENDC}")

                json_header['alg']='RS256'
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
                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs256_key=input()
                    def_key=RSAKeypairGen()
                    if not rs256_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS256 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS256')
                        str_encoded_RS256=encoded_RS256.decode('utf')
                    else:
                        encoded_RS256 = jwt.encode(json_mod_payload,rs256_key, algorithm='RS256')
                        str_encoded_RS256=encoded_RS256.decode('utf')

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS256':\n"+str(str_encoded_RS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

                elif not mod_payload:
                    print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                    json_header=str(json_header)
                    b64_Header = base64.b64encode(json_header.encode("utf-8"))
                    b64_encoded_header = str(b64_Header, "utf-8")
                    b64decoded_payload=str(b64decoded_payload)
                    b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                    b64_encoded_Payload = str(b64_Payload, "utf-8")
                    json_mod_payload=json.loads(b64decoded_payload)

                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs256_key=input()
                    def_key=RSAKeypairGen()
                    def_key=RSAKeypairGen()
                    if not rs256_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS256 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS256')
                        str_encoded_RS256=encoded_RS256.decode('utf')
                    else:
                        encoded_RS256 = jwt.encode(json_mod_payload,rs256_key, algorithm='RS256')
                        str_encoded_RS256=encoded_RS256.decode('utf')
                        
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS256':\n\n"+str(str_encoded_RS256)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except :                
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")
                
#######################################################################################
#Generate JWT Token with Algorithm type 'RS384'
#######################################################################################

        elif choice== '8':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
                print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

                #base64 encoded Header
                print("\nHeader="+Header)
                #base64 encoded Payload
                print("\nPayload="+Payload)
                #base64 encoded Signature
                print("\nSignature="+Signature)

                print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'RS384':{bcolors.ENDC}")

                json_header['alg']='RS384'
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
                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs384_key=input()
                    def_key=RSAKeypairGen()
                    if not rs384_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS384 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS384')
                        str_encoded_RS384=encoded_RS384.decode('utf')
                    else:
                        encoded_RS384 = jwt.encode(json_mod_payload,rs384_key, algorithm='RS384')
                        str_encoded_RS384=encoded_RS384.decode('utf')

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS384':\n"+str(str_encoded_RS384)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

                elif not mod_payload:
                    print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                    json_header=str(json_header)
                    b64_Header = base64.b64encode(json_header.encode("utf-8"))
                    b64_encoded_header = str(b64_Header, "utf-8")
                    b64decoded_payload=str(b64decoded_payload)
                    b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                    b64_encoded_Payload = str(b64_Payload, "utf-8")
                    json_mod_payload=json.loads(b64decoded_payload)

                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs384_key=input()
                    def_key=RSAKeypairGen()
                    if not rs384_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS384 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS384')
                        str_encoded_RS384=encoded_RS384.decode('utf')
                    else:
                        encoded_RS384 = jwt.encode(json_mod_payload,rs384_key, algorithm='RS384')
                        str_encoded_RS384=encoded_RS384.decode('utf')
                        
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS384':\n\n"+str(str_encoded_RS384)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except :                
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")  
                
#######################################################################################
#Generate JWT Token with Algorithm type 'RS512'
#######################################################################################

        elif choice== '9':
            try:
                part_jwt=in_jwt.split('.')
                Header=part_jwt[0]
                Payload=part_jwt[1]
                Signature=part_jwt[2]
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
                print(f"{bcolors.WARNING}\nBefore Algorithm Coversion:{bcolors.ENDC}")
                print("\nThe present algorithm of input JWT Token- "+f"{bcolors.OKGREEN}"+f"{bcolors.BOLD}"+ algo+f"{bcolors.UNDERLINE}{bcolors.ENDC}\n")

                #base64 encoded Header
                print("\nHeader="+Header)
                #base64 encoded Payload
                print("\nPayload="+Payload)
                #base64 encoded Signature
                print("\nSignature="+Signature)

                print(f"{bcolors.WARNING}\nAfter Algorithm Changed to 'RS512':{bcolors.ENDC}")

                json_header['alg']='RS384'
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
                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs512_key=input()
                    def_key=RSAKeypairGen()
                    if not rs512_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS512 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS512')
                        str_encoded_RS512=encoded_RS512.decode('utf')
                    else:
                        encoded_RS512 = jwt.encode(json_mod_payload,rs512_key, algorithm='RS512')
                        str_encoded_RS512=encoded_RS512.decode('utf')

                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS512':\n"+str(str_encoded_RS512)+f"{bcolors.OKGREEN}{bcolors.ENDC}")

                elif not mod_payload:
                    print(f"{bcolors.OKBLUE}\nThe payload is unchanged{bcolors.ENDC}")
                    json_header=str(json_header)
                    b64_Header = base64.b64encode(json_header.encode("utf-8"))
                    b64_encoded_header = str(b64_Header, "utf-8")
                    b64decoded_payload=str(b64decoded_payload)
                    b64_Payload = base64.b64encode(b64decoded_payload.encode("utf-8"))
                    b64_encoded_Payload = str(b64_Payload, "utf-8")
                    json_mod_payload=json.loads(b64decoded_payload)

                    print("\nEnter the Private key for generating the signature[if not, press ENTER for default key generation]:")
                    rs512_key=input()
                    def_key=RSAKeypairGen()
                    if not rs512_key:
                        print(f"{bcolors.OKGREEN}Public Key\n\n{bcolors.ENDC}"+str(def_key[0]))
                        print(f"{bcolors.OKGREEN}\n\nPrivate Key\n\n{bcolors.ENDC}"+str(def_key[1]))
                        encoded_RS512 = jwt.encode(json_mod_payload, def_key[1], algorithm='RS512')
                        str_encoded_RS512=encoded_RS512.decode('utf')
                    else:
                        encoded_RS512 = jwt.encode(json_mod_payload,rs512_key, algorithm='RS512')
                        str_encoded_RS512=encoded_RS512.decode('utf')
                        
                    print(f"{bcolors.OKGREEN}\nThe New JWT Token with Algorithm changed to 'RS512':\n\n"+str(str_encoded_RS512)+f"{bcolors.OKGREEN}{bcolors.ENDC}")
                else:
                    print("Not Valid Payload")
            except :                
                print(f"{bcolors.FAIL}\nThis is not a JWT Token. Please check again{bcolors.ENDC}\n")                  
#######################################################################################
# Exit
#######################################################################################

        elif choice=='10':
            exit()    
        else:
            print("Please select the correct number")
            print("Please try again\n\n")
            jwtWeak()

    else:
        print(f"{bcolors.FAIL}\nThis is not a valid input JWT Token{bcolors.ENDC}\n")

#######################################################################################
# Main
#######################################################################################

if __name__ == '__main__':
    jwtWeak()


 

