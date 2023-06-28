# ecdsa_threshold demo

## 1. GenerateDeviceData

The terminal calls GenerateDeviceData(), which generates three copies of data1, data2, and data3. 
data1 is stored on the server, data2 is stored on the terminal, and data3 is stored on the cloud.


```shell
cd generate_device_data
# params: keyPath
# output: save data1 data2 data3 to file
go run main.go ../../key
```

## 2. GetAddress

The terminal can call GetAddress(data1,data2) to get the wallet address


⚠️ TODO: need to split the data1 and data2 to two terminal. They will communicate using HTTP API.


```shell    
cd get_address
# params: data1 data2
# output: address
go run main.go ../../key/p1JsonData.json ../../key/p2JsonData.json
```

## 3. Sign

The terminal can call Sign(content,data1,data2) to sign the data

⚠️ TODO: need to split the data1 and data2 to two terminal. They will communicate using HTTP API.

### 3.1 Build tx

```shell
cd build_tx
# params: chainId toAddress nonce gasPrice  
# output: txDataHash
go run main.go '80001' '0x27a01491d86F3F3b3085a0Ebe3F640387DBdb0EC' '1000000' '4' '500000000000'
```

### 3.2 Sign tx

⚠️ TODO: need to split the data1 and data2 to two terminal. They will communicate using HTTP API.

```shell
cd sign
# params: data1 data2 txDataHash
# output: signature
go run main.go ../../key/p1JsonData.json ../../key/p2JsonData.json '85eb8167756e6513cb3c6c1041e99615db0df6c72c1a8a94e144fc0fc626884a'
```

### 3.2 Get tx raw data

```shell
cd build_tx
# params: chainId toAddress nonce gasPrice  
# output: txDataHash
go run main.go '80001' '0x27a01491d86F3F3b3085a0Ebe3F640387DBdb0EC' '1000000' '4' '500000000000' '4bf61e626b2488700fd093ba4fa7e9a95d6d64a9ae81dee4004c003ab08005111c823f47b328724d42df566fe90a12e7c57141e5ff05e5f2b4048fd822fbb01100'
```

## 4. Recover

The terminal can call Recover to refresh three copies of data


⚠️ TODO: need to split the data1 and data2 to two terminal. They will communicate using HTTP API.


```shell
cd recover
# params: data1 data2 data3 newKeyDirPath
# output: new data1 data2 data3 files
go run main.go ../../key/p1JsonData.json ../../key/p2JsonData.json ../../key/p3JsonData.json ../../key_new
```

