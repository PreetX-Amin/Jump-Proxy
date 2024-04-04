package main

import (
	"crypto/cipher"
	"fmt"
	"jumproxy/cryptography"

	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SERVER_TYPE = "tcp"
	SERVER_HOST = "localhost"
	CHUNK_SIZE  = 32 * 1024
)

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s\n", msg)
		panic(err)
	}
}

func argumentParser() (string, int, bool, int, string) {
	// Check the number of arguments
	args := os.Args[1:]
	if len(args) < 4 {
		fmt.Println("Invalid input arguments: too few arguments")
		fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
		os.Exit(1)
	}

	var keyFile, destination string
	var listen bool = false
	var port, listen_port int
	var err error
	// Check the key file
	for i := 0; i < len(args); i++ {
		if args[i] == "-k" {
			if i+1 >= len(args) {
				fmt.Println("Invalid input arguments: key file is missing")
				fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
				os.Exit(1)
			}

			keyFile = args[i+1]
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	// Check the listen port
	for i := 0; i < len(args); i++ {
		if args[i] == "-l" {
			listen = true
			listen_port, err = strconv.Atoi(args[i+1])
			checkError(err, "Invalid port number for listening")
			args = append(args[:i], args[i+2:]...)
			break
		}
	}

	// assert only 2 arguments left
	if len(args) != 2 {
		if len(args) < 2 {
			fmt.Println("Invalid input arguments: destination and/or port missing")
		} else {
			fmt.Println("Invalid input arguments: too many arguments")
		}
		fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
		os.Exit(1)
	}

	destination = args[0]
	port, err = strconv.Atoi(args[1])
	checkError(err, "Invalid destination port number")

	return destination, port, listen, listen_port, keyFile
}

func Receive(reader func([]byte) (int, error)) (int, []byte, error) {
	// Read the data from the connection
	var received int = 0
	buffer := []byte{}
	// Read the data in chunks.
	for {
		chunk := make([]byte, CHUNK_SIZE)
		read, err := reader(chunk)
		if err != nil {
			return received, buffer, err
		}
		received += read
		buffer = append(buffer, chunk[:read]...)

		if read == 0 || read < CHUNK_SIZE || received > 1024*1024 {
			break
		}
	}
	return received, buffer, nil
}

func portForward(reader func([]byte) (int, error), writer func([]byte) (int, error), crypto_func func(string, cipher.AEAD) string, wg *sync.WaitGroup, close *atomic.Bool, cipher *cipher.AEAD) {

	// Read from the reader and write to the writer
	var dBuffer string
	for {
		if close.Load() {
			wg.Done()
			return
		} else {
			mLen, buffer, err := Receive(reader)
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}

			dBuffer = crypto_func(string(buffer[:mLen]), *cipher)
			_, err = writer([]byte(dBuffer))
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func startClient(destination string, port int, passphraseFile string) {
	connection, err := net.Dial(SERVER_TYPE, destination+":"+strconv.Itoa(port))
	checkError(err, "Error connecting to server")
	defer connection.Close()

	// Read the passphrase from the file
	passphr, err := os.ReadFile(passphraseFile)
	checkError(err, "Error reading passphrase from file")
	passphrase := string(passphr)

	// Read the salt from the server and generate the key
	salt := make([]byte, 16)
	_, err = connection.Read(salt)
	checkError(err, "Error reading salt from server")

	// Generate the AES GCM cipher
	gcm, err := cryptography.GenerateAESGCMCipher(passphrase, salt)
	checkError(err, "Error generating AES GCM cipher")

	// Create a wait group
	var wg sync.WaitGroup
	var close atomic.Bool
	close.Store(false)

	// Start the send and receive channels
	wg.Add(2)
	go portForward(os.Stdin.Read, connection.Write, cryptography.Encrypt, &wg, &close, &gcm)
	go portForward(connection.Read, os.Stdout.Write, cryptography.Decrypt, &wg, &close, &gcm)
	wg.Wait()
}

func processClient(connection, forward net.Conn, passphrase string) {
	defer connection.Close()
	defer forward.Close()

	// Create salt and key and send to client
	salt, err := cryptography.GenerateRandomSalt(16)
	checkError(err, "Error generating salt")
	_, err = connection.Write(salt)
	checkError(err, "Error sending salt to client")

	// Generate the AES GCM cipher
	gcm, err := cryptography.GenerateAESGCMCipher(passphrase, salt)
	checkError(err, "Error generating AES GCM cipher")

	// Create a wait group
	var wg sync.WaitGroup
	var close atomic.Bool
	close.Store(false)

	// Start the send and receive channels
	wg.Add(2)
	go portForward(connection.Read, forward.Write, cryptography.Decrypt, &wg, &close, &gcm)
	go portForward(forward.Read, connection.Write, cryptography.Encrypt, &wg, &close, &gcm)
	wg.Wait()
	fmt.Println("Connection closed : ", connection.RemoteAddr())
}

func startServer(listen_port int, destination string, port int, passphraseFile string) {
	fmt.Println("Starting server...")
	server, err := net.Listen(SERVER_TYPE, ":"+strconv.Itoa(listen_port))
	checkError(err, "Error starting server")
	defer server.Close()
	fmt.Println("Listening on " + ":" + strconv.Itoa(listen_port))

	// Read the passphrase from the file
	passphr, err := os.ReadFile(passphraseFile)
	checkError(err, "Error reading passphrase from file")
	passphrase := string(passphr)

	// test destination connection
	forward_test, err := net.Dial(SERVER_TYPE, destination+":"+strconv.Itoa(port))
	checkError(err, "Error connecting to destination")
	defer forward_test.Close()

	for {
		connection, err := server.Accept()
		checkError(err, "Error accepting client")
		fmt.Println("client connected : ", connection.RemoteAddr())
		forward, err := net.Dial(SERVER_TYPE, destination+":"+strconv.Itoa(port))
		checkError(err, "Error connecting to destination")
		go processClient(connection, forward, passphrase)
	}
}

func main() {
	// Parse the arguments
	destination, port, listen, listen_port, keyFile := argumentParser()

	// Start the server
	if listen {
		startServer(listen_port, destination, port, keyFile)
	} else {
		startClient(destination, port, keyFile)
	}
}
