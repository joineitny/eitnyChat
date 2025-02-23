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
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
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
		logger.Printf("Ошибка при генерации ключей: %v", err)
		return nil, fmt.Errorf("ошибка генерации ключей: %w", err)
	}

	address := hex.EncodeToString(publicKey[:])
	logger.Printf("Сгенерирован новый пользователь с адресом: %s", address)
	return &User{
		PrivateKey: privateKey[:],
		PublicKey:  publicKey[:],
		Address:    address,
	}, nil
}

func deriveKey(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("пароль не может быть пустым")
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("неверный размер соли")
	}

	key := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	logger.Println("Ключ успешно сгенерирован с использованием Argon2id")
	return key, nil
}

func encryptMessage(key, message []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("неверный размер ключа")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		logger.Printf("Ошибка при создании AEAD: %v", err)
		return nil, fmt.Errorf("ошибка создания AEAD: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Printf("Ошибка при генерации nonce: %v", err)
		return nil, fmt.Errorf("ошибка генерации nonce: %w", err)
	}

	ciphertext := aead.Seal(nonce, nonce, message, nil)
	logger.Println("Сообщение успешно зашифровано")
	return ciphertext, nil
}

func decryptMessage(key, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("неверный размер ключа")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		logger.Printf("Ошибка при создании AEAD: %v", err)
		return nil, fmt.Errorf("ошибка создания AEAD: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("сообщение слишком короткое")
	}

	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		logger.Printf("Ошибка при расшифровке сообщения: %v", err)
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	logger.Println("Сообщение успешно расшифровано")
	return plaintext, nil
}

func handleConnection(conn net.Conn, user *User) {
	defer conn.Close()

	peerPublicKey := make([]byte, keySize)
	if _, err := io.ReadFull(conn, peerPublicKey); err != nil {
		logger.Printf("Ошибка при чтении публичного ключа: %v", err)
		return
	}

	sharedKey := new([keySize]byte)
	curve25519.ScalarMult(sharedKey, (*[keySize]byte)(user.PrivateKey), (*[keySize]byte)(peerPublicKey))

	message := []byte("Привет от P2P!")
	ciphertext, err := encryptMessage(sharedKey[:], message)
	if err != nil {
		logger.Printf("Ошибка при шифровании сообщения: %v", err)
		return
	}

	if _, err := conn.Write(ciphertext); err != nil {
		logger.Printf("Ошибка при отправке сообщения: %v", err)
		return
	}

	logger.Println("Сообщение успешно отправлено")
}

func startP2PServer(user *User) {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		logger.Fatalf("Ошибка при запуске сервера: %v", err)
	}
	defer listener.Close()

	logger.Println("Сервер запущен на 127.0.0.1:8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("Ошибка при принятии соединения: %v", err)
			continue
		}

		logger.Printf("Новое соединение от: %s", conn.RemoteAddr())
		go handleConnection(conn, user)
	}
}

func main() {
	logger.Println("Запуск P2P мессенджера...")

	// Генерация ключей для пользователя
	user, err := generateKeyPair()
	if err != nil {
		logger.Fatalf("Ошибка при генерации ключей пользователя: %v", err)
	}

	logger.Printf("Адрес пользователя: %s\n", user.Address)

	// Запуск P2P сервера в отдельной горутине
	go startP2PServer(user)

	// Настройка веб-сервера с использованием Gin
	router := gin.Default()

	// Загрузка статических файлов (HTML, CSS, JS)
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Маршрут для главной страницы
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"address": user.Address,
		})
	})

	// Маршрут для отправки сообщения
	router.POST("/send", func(c *gin.Context) {
		message := c.PostForm("message")
		logger.Printf("Получено сообщение: %s", message)

		// Пример шифрования и расшифровки
		password := []byte("supersecretpassword")
		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			logger.Fatalf("Ошибка при генерации соли: %v", err)
		}

		key, err := deriveKey(password, salt)
		if err != nil {
			logger.Fatalf("Ошибка при генерации ключа: %v", err)
		}

		ciphertext, err := encryptMessage(key, []byte(message))
		if err != nil {
			logger.Fatalf("Ошибка при шифровании сообщения: %v", err)
		}

		plaintext, err := decryptMessage(key, ciphertext)
		if err != nil {
			logger.Fatalf("Ошибка при расшифровке сообщения: %v", err)
		}

		c.JSON(http.StatusOK, gin.H{
			"encrypted": hex.EncodeToString(ciphertext),
			"decrypted": string(plaintext),
		})
	})

	// Запуск веб-сервера
	logger.Println("Веб-сервер запущен на http://localhost:8081")
	router.Run(":8081")
}
