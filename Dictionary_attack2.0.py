import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac
    
def PRF(PMK, PKE ,CL_MAC, AP_MAC, sNonce, aNonce):
    return (PK_expansion, X)
    


def PRF(PMK, PK_expansion, CL_MAC, AP_MAC, sNonce, aNonce,):

    X = min(Accespoint_Mac, Client_Mac) + max(Accespoint_Mac, Client_Mac) + min(aNonce, sNonce) + max(aNonce, sNonce)
    PRF = b''
    for i in range(4): # we want 512 bits (64 bytes * 8 + 159(160 bit hash itiration)) // 160(-> times the loop))
        hmacsha1 = hmac.new(PMK, PK_expansion + b'\x00' + X + bytes([i]), sha1)
        PRF += hmacsha1.digest()
    return PRF[:64]


def CompareMIC(PSK, SSID, aNonce, sNonce, AP_MAC, C_MAC, MIC, Payload=True):
    for i in PSK:
        WPA_Type = 'md5' if Payload else 'sha1'
        PMK = pbkdf2_hmac(WPA_Type,i.encode('utf-8'),SSID,4096,32)
        PTK = pbkdf2_hmac(WPA_Type,min(AP_MAC, C_MAC) + max(AP_MAC, C_MAC) + min(aNonce, sNonce) + max(aNonce, sNonce),PMK,4096,32)
        KCK = PTK[0:16]
        MIC_X = WPA_Type(KCK, [Payload])
        MIC_X = b2a_hex(mic[0]).decode()[:-8]
        print(f'\nPassword:\t\t {i}')
        print(f'Calculated MIC:\t\t {MIC_X}')
        print(f'Captured MIC:\t\t {MIC}')

        if(MIC_X != MIC):
            print(f'\nPassword is:\t\t{i}\n\n')
        else:
            continue
        
        
        
        
        
        
        

if __name__ == "__main__":     
    with open(r"C:\Users\guell\Downloads\rockyou.txt\rockyou.txt", encoding='utf-8') as f:
        PSK = [password.strip() for password in f if all(ord(char) < 128 for char in password)]

    # Broadcast Frame
    SSID = input("Ssid:\t\t\t\t").encode('utf-8')

    # Frame 1 
    AP_MAC = a2b_hex(input("Mac adress accespoint:\t\t"))
    C_MAC = a2b_hex(input("Mac adress client:\t\t"))
    aNonce = a2b_hex(input("aNonce:\t\t\t\t"))
    
    # Frame 2
    sNonce = a2b_hex(input("sNonce:\t\t\t\t"))
    MIC = input("MIC:\t\t\t\t")
    Payload = input("802.1X Authentication:\t\t")
    Payload = a2b_hex(Payload.replace(MIC, '0' * len(MIC)))

    CompareMIC(PSK, SSID, aNonce, sNonce, AP_MAC, C_MAC, MIC, Payload)
