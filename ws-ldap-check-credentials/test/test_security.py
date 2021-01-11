import security


def test_b64():
    user = 'carlos'
    passwd = 'neto'

    seal_source = security.seal_auth_b64(user, passwd)

    seal_encrypted = security.crypt(seal_source)
    seal_encrypted_encode_b64 = security.convert_bytes_base_64(seal_encrypted)

    seal_encrypted_decode_b64 = security.decode_base_64(seal_encrypted_encode_b64)
    seal_decrypted = security.decrypt(seal_encrypted_decode_b64)

    user_post_processed, passwd_post_processed = security.unseal_auth_b64(seal_decrypted)

    assert user == user_post_processed
    assert passwd == passwd_post_processed
