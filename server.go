package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
		if len(message) > aes.BlockSize {
			byt := decrypt("password", []byte(message[:len(message)-1]))
			var dat map[string]interface{}
			json.Unmarshal(byt, &dat)

			if dat != nil {
				fmt.Println("Message Received:", dat["message"].(string))

				outgoingMessage := &jMessage{
					Msg: dat["message"].(string),
				}
				outBytes, err := json.Marshal(outgoingMessage)
				if err != nil {
					continue
				}
				sendText := string(encrypt("password", outBytes))
				// send new string back to client
				conn.Write([]byte(sendText + "\x00"))
			}
		} else {
			time.Sleep(time.Millisecond * 5)
		}
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, _ := base64.StdEncoding.DecodeString(string(b))
	return data
}

func encrypt(key string, text []byte) []byte {
	paddedKey := fmt.Sprintf("%032s", key)
	block, _ := aes.NewCipher([]byte(paddedKey))

	b := encodeBase64(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], b)
	return ciphertext
}

func decrypt(key string, text []byte) []byte {
	paddedKey := fmt.Sprintf("%032s", key)
	block, _ := aes.NewCipher([]byte(paddedKey))

	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}
