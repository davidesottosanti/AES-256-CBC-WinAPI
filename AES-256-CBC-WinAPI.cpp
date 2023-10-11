#define DEFAULT_AES_KEY_SIZE 32
#define DEFAULT_IV_SIZE 16
#define BUFFER_FOR_PLAINTEXT 32

typedef struct AES256KEYBLOB_ {
	BLOBHEADER bhHdr;
	DWORD dwKeySize;
	BYTE szBytes[DEFAULT_AES_KEY_SIZE + 1];
} AES256KEYBLOB;

char* b64_AES_encryption(char** i_string, DWORD *b64_encrypted_size, DWORD**hex_key, DWORD* hex_key_size, DWORD**hex_iv, DWORD* hex_iv_size) {
	// handles for csp and key
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	BYTE *szKey = (BYTE*)calloc(DEFAULT_AES_KEY_SIZE + 1, sizeof(BYTE));
	BYTE *szIV = (BYTE*)calloc(DEFAULT_IV_SIZE + 1, sizeof(BYTE));
	char* ciphertext= 0;
	DWORD dwPlainSize = lstrlenA(*i_string), dwBufSize = 0;
	AES256KEYBLOB AESBlob;
	memset(&AESBlob, 0, sizeof(AESBlob));

	// create a cryptographic service provider (CSP)
	if (!CryptAcquireContextA(&hProv, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {goto clean_exit;}
	
	// Gen Key & IV
	if (!CryptGenRandom(hProv, DEFAULT_AES_KEY_SIZE, szKey)) { goto clean_exit; }
	if (!CryptGenRandom(hProv, DEFAULT_IV_SIZE, szIV)) { goto clean_exit; }
	
	// HEX KEY encoding
	DWORD hex_key_buff_size = 0;
	if (!CryptBinaryToStringA((BYTE*)szKey, DEFAULT_AES_KEY_SIZE, CRYPT_STRING_HEXRAW, NULL, &hex_key_buff_size)) { goto clean_exit; }
	char* hex_Key = (char*)calloc(hex_key_buff_size, sizeof(TCHAR));
	if (!CryptBinaryToStringA((BYTE*)szKey, DEFAULT_AES_KEY_SIZE, CRYPT_STRING_HEXRAW, (LPSTR)hex_Key, &hex_key_buff_size)) { goto clean_exit; }
	hex_Key[hex_key_buff_size - 2] = '\0';
	*hex_key = (DWORD*)hex_Key; *hex_key_size = hex_key_buff_size-2;
	
	// HEX iv encoding
	DWORD hex_iv_buff_size = 0;
	if (!CryptBinaryToStringA((BYTE*)szIV, DEFAULT_IV_SIZE, CRYPT_STRING_HEXRAW, NULL, &hex_iv_buff_size)) { goto clean_exit; }
	char* hex_Iv = (char*)calloc(hex_iv_buff_size, sizeof(TCHAR));
	if (!CryptBinaryToStringA((BYTE*)szIV, DEFAULT_IV_SIZE, CRYPT_STRING_HEXRAW, (LPSTR)hex_Iv, &hex_iv_buff_size)) { goto clean_exit; }
	hex_Iv[hex_iv_buff_size - 2] = '\0';
	*hex_iv = (DWORD*)hex_Iv; *hex_iv_size = hex_iv_buff_size-2;

	// blob data for CryptImportKey() function (include key and version and so on...)
	AESBlob.bhHdr.bType = PLAINTEXTKEYBLOB;
	AESBlob.bhHdr.bVersion = CUR_BLOB_VERSION;
	AESBlob.bhHdr.reserved = 0;
	AESBlob.bhHdr.aiKeyAlg = CALG_AES_256;
	AESBlob.dwKeySize = DEFAULT_AES_KEY_SIZE;
	StrCpyA((LPSTR)AESBlob.szBytes, (LPCSTR)szKey); // import KEY

	// populate crypto provider (CSP)
	if (!CryptImportKey(hProv, (BYTE*)&AESBlob, sizeof(AES256KEYBLOB), NULL, CRYPT_EXPORTABLE, &hKey)) { goto clean_exit; }
	if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)szIV, 0)) { goto clean_exit; } //import IV
	
	// ciphertext allocation
	dwBufSize = BUFFER_FOR_PLAINTEXT + dwPlainSize;
	ciphertext = (char*)calloc(dwBufSize, sizeof(char));
	memcpy_s(ciphertext, dwBufSize, *i_string, dwPlainSize);

	// encryption
	if (!CryptEncrypt(hKey, NULL, TRUE, 0, (BYTE*)ciphertext, &dwPlainSize, dwBufSize) ) { goto clean_exit; }

	// base64 encoding
	DWORD b64_buff_size = 0;
	if (!CryptBinaryToStringA((BYTE*)ciphertext, dwPlainSize, CRYPT_STRING_BASE64 , NULL, &b64_buff_size)) { goto clean_exit; }
	char* enc_creds = (char*)calloc(b64_buff_size, sizeof(TCHAR));
	if (!CryptBinaryToStringA((BYTE*)ciphertext, dwPlainSize, CRYPT_STRING_BASE64, (LPSTR)enc_creds, &b64_buff_size)) { goto clean_exit; }
	*b64_encrypted_size = b64_buff_size;

	*i_string = enc_creds;
	
clean_exit:
	if (ciphertext) free(ciphertext);
	if (hKey) CryptDestroyKey(hKey);
	if (hProv) CryptReleaseContext(hProv, 0);
	return NULL;

}
