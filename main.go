package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
)

const (
	keySize         = 32
	saltSize        = 16
	nonceSize       = 24
	argonTime       = 1
	argonMemory     = 64 * 1024
	argonThreads    = 4
	argonKeyLen     = 32
)

type User struct {
	PrivateKey []byte
	PublicKey  []byte
	Address    string
}

func generateKeyPair() (*User, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	address := hex.EncodeToString(publicKey[:])

	return &User{
		PrivateKey: privateKey[:],
		PublicKey:  publicKey[:],
		Address:    address,
	}, nil
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func encryptMessage(key, message []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(message)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nonce, nonce, message, nil)
	return ciphertext, nil
}

func decryptMessage(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func main() {
	// Генерация ключей для пользователя
	user, err := generateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("User Address: %s\n", user.Address)

	// Пример шифрования и расшифровки сообщения
	password := []byte("supersecretpassword")
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	key := deriveKey(password, salt)
	message := []byte("Hello, P2P World!")

	ciphertext, err := encryptMessage(key, message)
	if err != nil {
		log.Fatalf("Failed to encrypt message: %v", err)
	}

	plaintext, err := decryptMessage(key, ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}

	fmt.Printf("Decrypted Message: %s\n", plaintext)

	// Пример P2P соединения
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	fmt.Println("Listening on 127.0.0.1:8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, user)
	}
}

func handleConnection(conn net.Conn, user *User) {
	defer conn.Close()

	// Пример обмена ключами и шифрования сообщений
	peerPublicKey := make([]byte, keySize)
	if _, err := io.ReadFull(conn, peerPublicKey); err != nil {
		log.Printf("Failed to read peer public key: %v", err)
		return
	}

	sharedKey := new([keySize]byte)
	curve25519.ScalarMult(sharedKey, (*[keySize]byte)(user.PrivateKey), (*[keySize]byte)(peerPublicKey))

	// Шифрование и отправка сообщения
	message := []byte("Hello from P2P!")
	ciphertext, err := encryptMessage(sharedKey[:], message)
	if err != nil {
		log.Printf("Failed to encrypt message: %v", err)
		return
	}

	if _, err := conn.Write(ciphertext); err != nil {
		log.Printf("Failed to send message: %v", err)
		return
	}
}
