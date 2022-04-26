package securestorage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	"runtime"
)

//argon2 parameters
const (
	timeFactor = 10
	memoryKiB  = 256 * 1024
	keyLengthB = 32
)

//length of salt in bytes
const saltLen int = 16

func SaveBytes(key, plaintext []byte) (ct []byte, err error) {
	var blk cipher.Block
	var gcm cipher.AEAD

	//random salt
	var salt = make([]byte, saltLen)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}

	var dKey = Argon2Salt(key, salt)

	blk, err = aes.NewCipher(dKey)
	if err != nil {
		return nil, err
	}
	gcm, err = cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}

	//random nonce
	var nonce = make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ct = gcm.Seal(ct, nonce, plaintext, nil)

	//not ideal; good enough
	ct = append(salt, append(nonce, ct...)...)

	return
}

func LoadBytes(key, ciphertext []byte) (pt []byte, err error) {
	var blk cipher.Block
	var gcm cipher.AEAD

	var salt = ciphertext[:saltLen]

	//derive key from salt and provided key
	var dKey = Argon2Salt(key, salt)

	blk, err = aes.NewCipher(dKey)
	if err != nil {
		return nil, errors.New("aes key size error")
	}
	gcm, err = cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}

	var nonce = ciphertext[saltLen : saltLen+gcm.NonceSize()]

	pt, err = gcm.Open(pt, nonce, ciphertext[saltLen+gcm.NonceSize():], nil)
	if err != nil {
		return nil, errors.New("decryption/authentication error")
	}
	return
}

//func LoadFile(key []byte, file *os.File) (pt []byte, err error) {
//	var ct []byte
//
//	ct, err = ioutil.ReadAll(file)
//	if err != nil {
//		return nil, err
//	}
//
//	pt, err = LoadBytes(key, ct)
//	return
//}

func Argon2Salt(inkey, salt []byte) []byte {
	var n = runtime.NumCPU()
	if n > 255 {
		n = 255
	}
	return argon2.IDKey(inkey, salt, timeFactor, memoryKiB, uint8(n), keyLengthB)
}
