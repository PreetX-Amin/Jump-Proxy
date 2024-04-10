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
)

const (
	SERVER_TYPE = "tcp"
	SERVER_HOST = "localhost"
	CHUNK_SIZE  = 32 * 1024
)

var (
	logFile *os.File
)

func checkError(err error, msg string) {
	if err != nil {
		logFile.WriteString("Fatal error: " + msg + "\n")
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

func ReadChunkAndEncript(reader func([]byte) (int, error), cipher cipher.AEAD) (int, []byte, error) {
	// Read the data from the connection
	buffer := make([]byte, CHUNK_SIZE)
	read, err := reader(buffer)
	if err != nil {
		return read, buffer, err
	}

	// Get the length of the data and append it to the data first 4 bytes
	dataLen := fmt.Sprintf("%05d", read)
	buffer = append([]byte(dataLen), buffer...)

	// Encrypt the data
	encrypted := cryptography.Encrypt(string(buffer), cipher)

	return len(encrypted), []byte(encrypted), nil
}

func readPacket(reader func([]byte) (int, error)) (int, []byte, error) {
	// Read the data from the connection
	var received int = 0
	buffer := []byte{}
	// Read the data in chunks.
	for {
		chunk := make([]byte, CHUNK_SIZE+33-received)
		read, err := reader(chunk)
		if err != nil {
			return received, buffer, err
		}
		received += read
		buffer = append(buffer, chunk[:read]...)

		if read == 0 || read < CHUNK_SIZE+33-received {
			break
		}
	}
	return received, buffer, nil
}

func ReadChunkAndDecript(reader func([]byte) (int, error), cipher cipher.AEAD) (int, []byte, error) {
	// Read the data from the connection
	read, buffer, err := readPacket(reader)
	if err != nil {
		return read, buffer, err
	}

	// Decrypt the data
	decrypted := cryptography.Decrypt(string(buffer), cipher)

	// Get the length of the data
	length, err := strconv.Atoi(decrypted[:5])
	checkError(err, "Error converting length to integer")

	return length, []byte(decrypted[5:]), nil
}

func portForwardEncrypt(reader func([]byte) (int, error), writer func([]byte) (int, error), wg *sync.WaitGroup, close *atomic.Bool, cipher *cipher.AEAD) {
	// Read from the reader and write to the writer
	for {
		if close.Load() {
			wg.Done()
			return
		} else {
			mLen, buffer, err := ReadChunkAndEncript(reader, *cipher)
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}

			_, err = writer(buffer[:mLen])
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}
		}
	}
}

func portForwardDecrypt(reader func([]byte) (int, error), writer func([]byte) (int, error), wg *sync.WaitGroup, close *atomic.Bool, cipher *cipher.AEAD) {
	// Read from the reader and write to the writer
	for {
		if close.Load() {
			wg.Done()
			return
		} else {
			mLen, buffer, err := ReadChunkAndDecript(reader, *cipher)
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}

			_, err = writer(buffer[:mLen])
			if err != nil {
				close.Store(true)
				wg.Done()
				return
			}
		}
	}
}

func startClient(destination string, port int, passphraseFile string) {
	fmt.Println("Starting client...", destination, port)
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
	go portForwardEncrypt(os.Stdin.Read, connection.Write, &wg, &close, &gcm)
	go portForwardDecrypt(connection.Read, os.Stdout.Write, &wg, &close, &gcm)
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
	go portForwardEncrypt(forward.Read, connection.Write, &wg, &close, &gcm)
	go portForwardDecrypt(connection.Read, forward.Write, &wg, &close, &gcm)
	wg.Wait()
	fmt.Println("Connection closed : ", connection.RemoteAddr())
}

func startServer(listen_port int, destination string, port int, passphraseFile string) {

	// test destination connection
	forward_test, err := net.Dial(SERVER_TYPE, destination+":"+strconv.Itoa(port))
	checkError(err, "Error connecting to destination")
	forward_test.Close()

	fmt.Println("Starting server...")
	server, err := net.Listen(SERVER_TYPE, ":"+strconv.Itoa(listen_port))
	checkError(err, "Error starting server")
	defer server.Close()
	fmt.Println("Listening on " + ":" + strconv.Itoa(listen_port))

	// Read the passphrase from the file
	passphr, err := os.ReadFile(passphraseFile)
	checkError(err, "Error reading passphrase from file")
	passphrase := string(passphr)

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
		logFile, _ = os.OpenFile("../jumproxy_server.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		startServer(listen_port, destination, port, keyFile)
	} else {
		logFile, _ = os.OpenFile("../jumproxy_client.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		startClient(destination, port, keyFile)
	}
}
