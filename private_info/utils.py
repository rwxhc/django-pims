
from gmssl import sm3, sm4, func
import base64


# sm3 hash，用于存储密码，仅用于密码比对
def uf_hash(input:str)->str:
    return sm3.sm3_hash(func.bytes_to_list(input.encode()))


# sm4加密数据，用base64编码
def uf_encrypt(input:str, key:str)->str:
    iv = 'huangcheng123456'.encode()
    hash_key = uf_hash(key)
    bytes_key = bytes.fromhex(hash_key)[0:16]
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(bytes_key, sm4.SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_cbc(iv, input.encode())
    return base64.b64encode(encrypt_value).decode()


# 解密数据，先用base64解码，再用sm4解密
# 返回空为失败，其他为成功
def uf_decrypt(input:str, key:str)->str:
    iv = 'huangcheng123456'.encode()
    hash_key = uf_hash(key)
    bytes_key = bytes.fromhex(hash_key)[0:16]
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(bytes_key, sm4.SM4_DECRYPT)

    try:
        b_input = base64.b64decode(input.encode())
        decrypt_value = crypt_sm4.crypt_cbc(iv, b_input)
        return decrypt_value.decode()
    except Exception as e:
        return ""

