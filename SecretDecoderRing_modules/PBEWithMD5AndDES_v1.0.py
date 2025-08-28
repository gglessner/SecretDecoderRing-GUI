from Crypto.Cipher import DES
from Crypto.Hash import MD5
from Crypto.Util.Padding import unpad

def decrypt(iv, key, ciphertext):
    """
    Attempts to decrypt the ciphertext using PBEWithMD5AndDES.
    
    This implements the PKCS#5 Password-Based Encryption standard using:
    - MD5 for key derivation
    - DES for encryption
    - PKCS#7 padding
    
    The key parameter is treated as the password, and the IV as the salt.
    If no salt is provided, a default salt of 8 zero bytes is used.

    Args:
        iv (bytes): Salt for key derivation (typically 8 bytes, but can be variable).
        key (bytes): Password for key derivation (variable length).
        ciphertext (bytes): Ciphertext to decrypt.

    Returns:
        list: A list of tuples (mode_name, plaintext) for each successful decryption.
              Returns an empty list if no mode succeeds.
    """
    results = []
    
    # Minimum requirements
    if len(ciphertext) < 8 or len(ciphertext) % 8 != 0:
        return results
    
    def try_utf8(data):
        """Check if data can be decoded as UTF-8"""
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False
    
    def derive_key_iv_pbe(password, salt, iteration_count=1000):
        """
        Derive key and IV using PBE with MD5 (PKCS#5 style).
        
        Args:
            password (bytes): Password for derivation
            salt (bytes): Salt for derivation (8 bytes for DES)
            iteration_count (int): Number of iterations
            
        Returns:
            tuple: (key, iv) where key is 8 bytes for DES and iv is 8 bytes
        """
        # Concatenate password and salt
        data = password + salt
        
        # Apply MD5 hash iterations
        digest = data
        for _ in range(iteration_count):
            digest = MD5.new(digest).digest()
        
        # DES key is 8 bytes, IV is 8 bytes
        derived_key = digest[:8]
        derived_iv = digest[8:16]
        
        return derived_key, derived_iv
    
    # Determine salt to use
    salt = iv if iv else b'\x00' * 8  # Use provided iv as salt, or zero salt if none
    
    # Try iterations from 1 to 5000 to match the working code
    for iterations in range(1, 5001):
        try:
            # Derive key and IV
            derived_key, derived_iv = derive_key_iv_pbe(key, salt[:8], iterations)
            
            # Try CBC mode with derived IV
            try:
                cipher = DES.new(derived_key, DES.MODE_CBC, derived_iv)
                pt_padded = cipher.decrypt(ciphertext)
                
                # Try to unpad
                try:
                    pt = unpad(pt_padded, DES.block_size)
                    if try_utf8(pt):
                        mode_name = f"PBE-MD5-DES-CBC-Salt{salt.hex()[:8] if salt else 'None'}-Iter{iterations}"
                        results.append((mode_name, pt))
                except ValueError:
                    pass  # Invalid padding
                    
            except Exception:
                pass
            
            # Try ECB mode (less common for PBE but possible)
            try:
                cipher = DES.new(derived_key, DES.MODE_ECB)
                pt_padded = cipher.decrypt(ciphertext)
                
                # Try to unpad
                try:
                    pt = unpad(pt_padded, DES.block_size)
                    if try_utf8(pt):
                        mode_name = f"PBE-MD5-DES-ECB-Salt{salt.hex()[:8] if salt else 'None'}-Iter{iterations}"
                        results.append((mode_name, pt))
                except ValueError:
                    pass  # Invalid padding
                    
            except Exception:
                pass
            
        except Exception:
            continue
    
    return results