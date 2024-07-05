CSE508: Network Security, Spring 2024
Name: Preet Amin | Student ID: 115360499

Homework 3: Jump Proxy
-------------------------------------------------------------------------------

# Introduction

This Go module implements a simple TCP port-forwarding proxy with encryption 
and decryption capabilities. The proxy can act as a client or a server, 
forwarding data between a client and a server while encrypting and decrypting 
it using AES-GCM. The proxy provides a secure channel for communication between
the client and the server.

The relevant files in this can be found in the `jumproxy` directory. The main
file is `jumproxy.go`, which contains the implementation of the jump proxy.

The directory structure is as follows:
```
jumproxy/
    ├── cryptography/
    │   └── cryptography.go
    ├── jumproxy.go
    ├── go.mod
    └── mykey
```

The `cryptography` package contains the implementation of the encryption and
decryption functions using AES-GCM. The `jumpproxy.go` file contains the main
implementation of the jump proxy, including the client and server logic.


# Building and Running the Jump Proxy
First, change the directory to the `jumproxy` directory:

To run the jump proxy without building it, you can use the following command:
```
go run jumpproxy.go -k <encription-key-file> [-l port] <destination> <port>
```

To build the jump proxy, you can use the following command:
```
go build jumpproxy.go
./jumpproxy -k <encription-key-file> [-l port] <destination> <port>
```

The command-line arguments are as follows:
- `-k`: Specifies the path to the file containing the encryption key.
- `-l`: Specifies the port on which the proxy should listen for incoming 
        connections.
- `<destination>`: Specifies the destination address to which the proxy should 
                   forward the data.
- `<port>`: Specifies the port on the destination address to which the proxy 
            should forward the data.

The jump proxy can act as a client or a server based on the command-line 
arguments. When acting as a client, the proxy forwards data from stdin to the
server and from the server to stdout. When acting as a server, the proxy 
listens for incoming connections on the listening port and forwards data
between the client and the destination address.

# Example Usage of the Jump Proxy for SSH

To start the jump proxy server on the local machine, you can use the following
command:
```
go build jumpproxy.go
./jumpproxy -k mykey -l <port> localhost 22
```
or
```
go run jumpproxy.go -k mykey -l <port> localhost 22
```

To connect to an SSH server using the jump proxy, you can use the following
command:
```
go build jumpproxy.go
ssh -o "ProxyCommand ./jumpproxy -k mykey <ip> <port>" <user>@localhost
```
or
```
ssh -o "ProxyCommand go run jumpproxy.go -k mykey <ip> <port>" <user>@localhost
```


# Code Overview

`cryptography/cryptography.go`:
-------------------------------

This file contains the implementation of some helper functions for generating 
a salt, deriving a cipher, and encrypting/decrypting data using AES-GCM.

    Imports:
    - `crypto/aes` and `crypto/cipher`: For AES encryption. 
    - `crypto/rand`: For generating random values.
    - `crypto/sha512`: For hashing.
    - `fmt`: For formatted I/O.
    - `math/big`: For arbitrary-precision arithmetic.
    - `os`: For file operations.
    - `golang.org/x/crypto/pbkdf2`: For key derivation.

    Functions:
    - `GenerateRandomSalt(length int)`: Generates a random salt 
      of the specified length.

    - `GenerateAESGCMCipher(passphrase string, salt []byte)`: 
      Derives an AES-GCM cipher from the passphrase and salt.

    - `Encrypt(plaintext []byte, gcm cipher.AEAD)`: Encrypts the plaintext 
      using the AES-GCM cipher.

    - `Decrypt(ciphertext []byte, gcm cipher.AEAD)`: Decrypts the 
      ciphertext using the AES-GCM cipher.


`jumproxy.go`:
--------------

This file contains the implementation of the jump proxy, including the client
and server logic.

    Imports:
    - `crypto/cipher`: For encryption and decryption.
    - `jumpproxy/cryptography`: For encryption/decryption and helper functions.
    - `encoding/binary`: For encoding and decoding binary data.
    - `fmt`: For formatted I/O.
    - `flag`: For command-line argument parsing.
    - `net`: For networking operations.
    - `os`: For file operations.
    - `strconv`: For string conversions.
    - `sync` and `sync/atomic`: For synchronization primitives.

    Constants and Variables:
    - `SERVER_TYPE`, `SERVER_HOST`, and `CHUNK_SIZE`: Constants defining server 
      type, host, and chunk size.
    - `keyFile`, `port`, and `help`: Flags for command-line arguments.

    Functions:
    - `checkError(err error)`: Helper function for handling errors.

    - `argumentParser()`: Parses command-line arguments.

    - `readChunkAndEncrypt(conn net.Conn, gcm cipher.AEAD) ([]byte, int)`: 
      Reads data from a connection, encrypts it, and returns the encrypted data 
      along with its length. It appends the length of the encripted data to the
      beginning of the data. The lingth is appended as 4 bytes integer (little 
      endian uint32) and not encripted.

    - `readChunkAndDecrypt(conn net.Conn, gcm cipher.AEAD) ([]byte, int)`: 
      Reads data from a connection, decrypts it, and returns the decrypted data 
      along with its length. It reads the length of the encripted data from the
      beginning of the data. Based on the length, it reads the data and 
      decrypts it.

    - `portForwardEncrypt(src, dest net.Conn, 
                          gcm cipher.AEAD, 
                          wg *sync.WaitGroup, 
                          close *atomic.Value)`: 
      Forwards data between two connections while encrypting it. Uses WaitGroup
      and atomic boolean to coordinate termination. uses `readChunkAndEncrypt`.

    - `portForwardDecrypt(src, dest net.Conn, 
                          gcm cipher.AEAD, 
                          wg *sync.WaitGroup, 
                          close *atomic.Value)`: 
      Forwards data between two connections while decrypting it. Uses WaitGroup
      and atomic boolean to coordinate termination. uses `readChunkAndDecrypt`.

    - `startClient(destAddr string, destPort string)`: Starts a client 
      connection to a destination address and port. It reads a passphrase from 
      a file, recieves a salt from the server to derive an AES-GCM cipher. It 
      then starts two goroutines to forward encrypted data from stdin to the 
      server and decrypted data from the server to stdout.

    - `processClient(conn net.Conn)`: Handles the client's connection to the 
      server. It exchanges a salt with the client, derives an AES-GCM cipher, 
      and starts two goroutines to forward encrypted data from the client to 
      the server and decrypted data from the server to the client.

    - `startServer(port string)`: Starts a server on a specified port and 
      listens for incoming connections. For each incoming connection, it 
      establishes a forward connection to the destination address and port. It 
      then spawns a goroutine to handle the connection using `processClient`.

    - `main()`: The entry point of the program. Parses command-line arguments, 
      opens a log file, and starts a server or a client based on the 
      command-line arguments.

-------------------------------------------------------------------------------
