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
	"os"
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

var logger = log.New(os.Stdout, "P2P-Messenger: ", log.LstdFlags|log.Lshortfile)

func generateKeyPair() (*User, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		logger.Printf("Failed to generate key pair: %v", err)
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	address := hex.EncodeToString(publicKey[:])

	logger.Printf("Generated new user with address: %s", address)
	return &User{
		PrivateKey: privateKey[:],
		PublicKey:  publicKey[:],
		Address:    address,
	}, nil
}

func deriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("invalid salt size")
	}

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	logger.Println("Derived key using Argon2id")
	return key, nil
}

func encryptMessage(key, message []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		logger.Printf("Failed to create XChaCha20-Poly1305 AEAD: %v", err)
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Printf("Failed to generate nonce: %v", err)
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, message, nil)
	logger.Println("Message encrypted successfully")
	return ciphertext, nil
}

func decryptMessage(key, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		logger.Printf("Failed to create XChaCha20-Poly1305 AEAD: %v", err)
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logger.Printf("Failed to decrypt message: %v", err)
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	logger.Println("Message decrypted successfully")
	return plaintext, nil
}

func main() {
	logger.Println("Starting P2P Messenger...")

	// Генерация ключей для пользователя
	user, err := generateKeyPair()
	if err != nil {
		logger.Fatalf("Failed to generate user key pair: %v", err)
	}

	logger.Printf("User Address: %s\n", user.Address)

	// Пример шифрования и расшифровки сообщения
	password := []byte("supersecretpassword")
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		logger.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := deriveKey(password, salt)
	if err != nil {
		logger.Fatalf("Failed to derive key: %v", err)
	}

	message := []byte("Hello, P2P World!")
	ciphertext, err := encryptMessage(key, message)
	if err != nil {
		logger.Fatalf("Failed to encrypt message: %v", err)
	}

	plaintext, err := decryptMessage(key, ciphertext)
	if err != nil {
		logger.Fatalf("Failed to decrypt message: %v", err)
	}

	logger.Printf("Decrypted Message: %s\n", plaintext)

	// Пример P2P соединения
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		logger.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	logger.Println("Listening on 127.0.0.1:8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("Failed to accept connection: %v", err)
			continue
		}

		logger.Printf("New connection from: %s", conn.RemoteAddr())
		go handleConnection(conn, user)
	}
}

func handleConnection(conn net.Conn, user *User) {
	defer conn.Close()

	// Чтение публичного ключа от пира
	peerPublicKey := make([]byte, keySize)
	if _, err := io.ReadFull(conn, peerPublicKey); err != nil {
		logger.Printf("Failed to read peer public key: %v", err)
		return
	}

	// Генерация общего ключа
	sharedKey := new([keySize]byte)
	curve25519.ScalarMult(sharedKey, (*[keySize]byte)(user.PrivateKey), (*[keySize]byte)(peerPublicKey))

	// Шифрование и отправка сообщения
	message := []byte("Hello from P2P!")
	ciphertext, err := encryptMessage(sharedKey[:], message)
	if err != nil {
		logger.Printf("Failed to encrypt message: %v", err)
		return
	}

	if _, err := conn.Write(ciphertext); err != nil {
		logger.Printf("Failed to send message: %v", err)
		return
	}

	logger.Println("Message sent successfully")
}
