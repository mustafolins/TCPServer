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
	"os"
	"time"
)

type jMessage struct {
	Msg string `json:"message"`
}

func main() {
	port := "3000"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	fmt.Println("Launching server...")

	// listen on all interfaces
	ln, _ := net.Listen("tcp", ":"+port)

	// accept connection on port
	conn, _ := ln.Accept()

	// run loop forever (or until ctrl-c)
	for {
		// will listen for message to process ending in newline (\x00)
		reader := bufio.NewReader(conn)
		message, recErr := reader.ReadString('\x00')
		for reader.Buffered() > 0 {
			// the delim might get hit do to encryption check for this and append to message
			extraMessage, recErr := reader.ReadString('\x00')
			if recErr != nil {
				break
			}
			message += extraMessage
		}
		if recErr != nil {
			continue
		}
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
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		fmt.Println(err)
		fmt.Println(string(data))
		fmt.Println(string(b))
	}
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
	block, err := aes.NewCipher([]byte(paddedKey))
	if err != nil {
		fmt.Println(err)
	}

	if len(text) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return decodeBase64(text)
}
