package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net" // only needed below for sample processing
	"time"
)

type jMessage struct {
	Msg string `json:"message"`
}

func main() {

	fmt.Println("Launching server...")

	// listen on all interfaces
	ln, _ := net.Listen("tcp", ":3000")

	// accept connection on port
	conn, _ := ln.Accept()

	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\x00)
		message, _ := bufio.NewReader(conn).ReadString('\x00')
		// output message received
		if len(message) > 0 {
			byt := decrypt([]byte(message[:len(message)-1]), "password")
			var dat map[string]interface{}
			json.Unmarshal(byt, &dat)

			fmt.Println("Message Received:", dat["message"].(string))

			outgoingMessage := &jMessage{
				Msg: dat["message"].(string),
			}
			outBytes, err := json.Marshal(outgoingMessage)
			if err != nil {
				continue
			}
			sendText := string(encrypt([]byte(outBytes), "password"))
			// send new string back to client
			conn.Write([]byte(sendText + "\x00"))
		} else {
			time.Sleep(time.Millisecond * 5)
		}
	}
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}
