def autokey_encrypt(plaintext, key):  
    ciphertext = []  
    key = key.upper()  
    plaintext = plaintext.upper()  
    key_stream = list(key) + [c for c in plaintext[:-len(key)]]  
    
    for p, k in zip(plaintext, key_stream):  
        if p.isalpha():  
            shift = (ord(p) + ord(k) - 2 * ord('A')) % 26  
            ciphertext.append(chr(shift + ord('A')))  
        else:  
            ciphertext.append(p)  
    return ''.join(ciphertext)  

def autokey_decrypt(ciphertext, key):  
    plaintext = []  
    key = key.upper()  
    ciphertext = ciphertext.upper()  
    key_stream = list(key)  
    
    for i, c in enumerate(ciphertext):  
        if c.isalpha():  
            p = (ord(c) - ord(key_stream[i]) + 26) % 26  
            plaintext.append(chr(p + ord('A')))  
            key_stream.append(plaintext[-1])  
        else:  
            plaintext.append(c)  
    return ''.join(plaintext)  

# Example Usage  
plaintext = "HELLO"  
key = "KEY"  
ciphertext = autokey_encrypt(plaintext, key)  
decrypted = autokey_decrypt(ciphertext, key)  
print("Encrypted:", ciphertext)  
print("Decrypted:", decrypted)  