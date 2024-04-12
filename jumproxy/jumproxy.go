package main

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"jumproxy/cryptography"

	"flag"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
)

const (
	SERVER_TYPE = "tcp"
	SERVER_HOST = "localhost"
	CHUNK_SIZE  = 64 * 1024
)

var (
	logFile *os.File
	keyFile = flag.String("k", "", "encription-key-file")
	port    = flag.String("l", "", "listen port for server")
	help    = flag.Bool("h", false, "help")
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
	flag.Parse()
	if *help {
		fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
		os.Exit(0)
	}

	// Check if key file is provided
	if *keyFile == "" {
		fmt.Println("Invalid input arguments: key file is missing")
		fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
		os.Exit(1)
	}

	// Check if listen port is provided
	listen := false
	listen_port, err := strconv.Atoi(*port)
	if *port != "" {
		checkError(err, "Invalid port number for listening")
		listen = true
	}

	// Get the destination and port
	args := flag.Args()
	if len(args) != 2 {
		if len(args) < 2 {
			fmt.Println("Invalid input arguments: destination and/or port missing")
		} else {
			fmt.Println("Invalid input arguments: too many arguments")
		}
		fmt.Println("Usage: ", os.Args[0], " -k <encription-key-file> [-l port] <destination> <port>")
		os.Exit(1)
	}

	destination := args[0]
	port, err := strconv.Atoi(args[1])
	checkError(err, "Invalid destination port number")

	return destination, port, listen, listen_port, *keyFile
}

func readChunkAndEncript(reader func([]byte) (int, error), cipher cipher.AEAD) (int, []byte, error) {
	// Read the data from the connection
	buffer := make([]byte, CHUNK_SIZE)
	read, err := reader(buffer)
	if err != nil {
		return read, buffer, err
	}

	// Encrypt the data
	encrypted := cryptography.Encrypt(buffer[:read], cipher)

	// Get the length of the data and append it to the data first 4 bytes
	byte_len := make([]byte, 4)
	binary.LittleEndian.PutUint32(byte_len, uint32(len(encrypted)))
	encrypted = append(byte_len, encrypted...)

	return len(encrypted), encrypted, nil
}

func readChunkAndDecript(reader func([]byte) (int, error), cipher cipher.AEAD) (int, []byte, error) {
	// Read the data from the connection
	packet_len := make([]byte, 4)
	read, err := reader(packet_len)
	if err != nil {
		return read, packet_len, err
	}
	if read == 0 {
		return read, packet_len, fmt.Errorf("EOF: Error reading from connection")
	}

	// Get the length of the data
	length := int(binary.LittleEndian.Uint32(packet_len))

	// read the data
	buffer := make([]byte, length)
	read, err = reader(buffer)
	if err != nil {
		return read, buffer, err
	}

	// Decrypt the data
	decrypted := cryptography.Decrypt(buffer, cipher)

	return len(decrypted), decrypted, nil
}

func portForwardEncrypt(reader func([]byte) (int, error), writer func([]byte) (int, error), wg *sync.WaitGroup, close *atomic.Bool, cipher *cipher.AEAD) {
	// Read from the reader and write to the writer
	defer wg.Done()
	defer close.Store(true)
	for {
		if close.Load() {
			return
		} else {
			mLen, buffer, err := readChunkAndEncript(reader, *cipher)
			if err != nil {
				return
			}

			_, err = writer(buffer[:mLen])
			if err != nil {
				return
			}
		}
	}
}

func portForwardDecrypt(reader func([]byte) (int, error), writer func([]byte) (int, error), wg *sync.WaitGroup, close *atomic.Bool, cipher *cipher.AEAD) {
	// Read from the reader and write to the writer
	defer wg.Done()
	defer close.Store(true)
	for {
		if close.Load() {
			return
		} else {
			mLen, buffer, err := readChunkAndDecript(reader, *cipher)
			if err != nil {
				return
			}

			_, err = writer(buffer[:mLen])
			if err != nil {
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
