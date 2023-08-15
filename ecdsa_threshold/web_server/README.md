# Ecdsa Threshold Signature On Web


## Tips

> ⚠️ This code cannot be used directly in a production environment

1. Authentication is not implemented on server side. So the server is not secure.
2. Nodejs is used to run wasm code. It is not necessary. You can use other language to run wasm code.
3. Nodejs lacks a step to write the private key to a client-local file. So the private key is not secure.

## Introduction

This is a simple HTTP server for ecdsa threshold. It is used to receive the message from the client and send the response to the client.
Then the client will use the response to generate the data what they need.

## Dependencies

- Go: 1.19
- Nodejs: 14.x


## Installation

### Install Go(Linux)

```bash
# Download Go
wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
# Unzip
tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
# Add to PATH
export PATH=$PATH:/usr/local/go/bin
```

### Install Nodejs(Linux)

```bash
# Download Nodejs
wget https://nodejs.org/dist/v14.17.6/node-v14.17.6-linux-x64.tar.xz
# Unzip
tar -C /usr/local -xzf node-v14.17.6-linux-x64.tar.xz
# Add to PATH
export PATH=$PATH:/usr/local/node-v14.17.6-linux-x64/bin
```

### Install Dependencies

```bash
# Install go dependencies
cd server
go mod download
```
    
```bash
# Install nodejs dependencies
cd nodejs
npm install
```

```bash
# Build wasm code
cd nodejs/gocmd
./build_wasm.sh
```

## Usage

### Run Server
    
```bash
cd server
go run main.go
```

### Run Nodejs

```bash
cd nodejs
node main.js
```

