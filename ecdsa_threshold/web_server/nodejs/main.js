const http = require("http");
const wasmFile = require('path').resolve(__dirname, './gocmd/main.wasm');
const JSONBig = require('json-bigint');

// const randomPrime = generateRandomPrime();
// console.log(randomPrime);
// 创建一个自定义的JSON解析器
const JSONBigInt = JSONBig({
    storeAsString: true, // 将大整数存储为字符串
    strict: true, // 启用严格模式，禁用科学计数法
});


function request(url, method, data) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        },
    };

    return new Promise(function (resolve, reject) {
        const req = http.request(url, options, function (res) {
            let responseData = '';

            res.setEncoding('utf8');

            res.on('data', function (chunk) {
                responseData += chunk;
            });

            res.on('end', function () {
                try {
                    const response = JSONBigInt.parse(responseData);
                    if (response.code === 200) {
                        resolve(response.data);
                    } else {
                        reject(new Error('Request failed with code: ' + response.code));
                    }
                } catch (error) {
                    reject(error);
                }
            });
        });

        req.on('error', function (error) {
            console.error('Request failed:', error);
            reject(error);
        });

        if (data) {
            req.write(JSONBigInt.stringify(data));
        }

        req.end();
    });
}

function main() {
    require('./run_wasm')(wasmFile).then(async () => {
        // generate device data(three keys)
        const keys = generateDeviceData();
        let keysJson = JSONBigInt.parse(keys);
        if (keysJson["code"] === 200) {
            console.log("p1JsonData: " + JSONBigInt.stringify(keysJson["data"]["p1JsonData"]));
            console.log("p2JsonData: " + JSONBigInt.stringify(keysJson["data"]["p2JsonData"]));
            console.log("p3JsonData: " + JSONBigInt.stringify(keysJson["data"]["p3JsonData"]));
        } else {
            console.log("generateDeviceData error. Response: " + keys);
        }

        // get address
        // params: p1 key, p2 id, random prim1, random prim2
        console.log("start to initP1KeyData")
        const initP1KeyDataRes = initP1KeyData(
            "{\"Id\":1,\"ShareI\":232032738015542844233121271557124288275480479062149352227252084605705136816362,\"PublicKey\":{\"Curve\":\"secp256k1\",\"X\":75875034985290753681653793737122640912175216206973254645208674727382786017143,\"Y\":85602415170691505007890581492987054634909916556952194804148723557453340366522},\"ChainCode\":\"01fd54b04cdf34a165937a9fe04e130c6529621efb08bb602d911fa5266a741f9a\",\"SharePubKeyMap\":{\"1\":{\"Curve\":\"secp256k1\",\"X\":82970345141697773068586555302681155066951871919056401360514398697435972494872,\"Y\":26885489115859529197224138413486061757450153616985244434332779849802209012706},\"2\":{\"Curve\":\"secp256k1\",\"X\":63385106301626776740551571723733420414877079050183909259495750428493581412138,\"Y\":58608427650676582365972774502027846536810279772453291868569569424685293603724},\"3\":{\"Curve\":\"secp256k1\",\"X\":3098167895008803067226693185553816864584286576801179702237603660070036111497,\"Y\":81594039034702707699844980188821393243087781498759139736971032436521454779682}}}"
        );
        console.log("initP1KeyData: ", initP1KeyDataRes);

        // get address
        // params: p1 key, p2 id, random prim1, random prim2
        console.log("start to get address")
        console.log("start to get random prim(each client only needs to get it once)")
        let primResult = await request("http://127.0.0.1:8080/api/v1/random-prim", "GET", null);
        console.log("primResult:", primResult);

        const prim1 = primResult["p"];
        const prim2 = primResult["q"];
        const keyGenMessage = keyGenRequestMessage(2, prim1, prim2);
        console.log("Generate Key Request Message: ", keyGenMessage);
        let keyGenMessageJson = JSONBigInt.parse(keyGenMessage);
        console.log(keyGenMessageJson["data"]);

        console.log("start to bind-user-p2")
        let bindResult = await request("http://127.0.0.1:8080/api/v1/bind-user-p2", "POST", {
            "p1_message_dto": keyGenMessageJson["data"],
            "p1_data_id": 1,
            "p2_key_file_name": "test1/p2.json",
            "user_name": "zhangsan"
        });
        console.log("bindResult:", bindResult);

        // send http request to get address
        console.log("start to get address")
        let getAddressAndPubKeyRes = await request("http://127.0.0.1:8080/api/v1/get-address", "POST", {
            "user_name": "zhangsan"
        })
        const address = getAddressAndPubKeyRes["address"];
        const pubKey = getAddressAndPubKeyRes["pub_key"];
        console.log("Address: " + address);
        console.log("PubKey: " + pubKey);

        const message = "85eb8167756e6513cb3c6c1041e99615db0df6c72c1a8a94e144fc0fc626884a";
        // send http request to get address
        console.log("start to init-p2-content")
        let initP2ContentRes = await request("http://127.0.0.1:8080/api/v1/init-p2-content", "POST", {
            "user_name": "zhangsan",
            "message": message
        })
        console.log("initP2ContentRes: ", initP2ContentRes);
        // sign
        // Step 0
        // params: p1 key, p2 id, random prim1, random prim2
        const initPubKeyRes = initPubKey(pubKey);
        console.log(`initPubKey: ${initPubKeyRes}`);

        const initP1ContextRes = initP1Context(message);
        console.log(`initP1Context: ${initP1ContextRes}`);

        // p1 step1
        const p1Step1Res = p1Step1();
        console.log(`p1Step1: ${p1Step1Res}`);

        // p2 step1
        let p2Step1Result = await request("http://127.0.0.1:8080/api/v1/p2-step1", "POST", {
            "user_name": "zhangsan",
            "commitment": JSONBigInt.parse(p1Step1Res)["data"],
        })
        console.log("p2Step1Result: ", p2Step1Result);

        let proofJson = p2Step1Result["proof"]
        parseNumbers(proofJson)
        console.log("p2Step1Result proofJsonStr: ", JSONBigInt.stringify(proofJson));

        let ecpointJson = p2Step1Result["ecpoint"]
        parseNumbers(ecpointJson)
        console.log("p2Step1Result ecpointJsonStr: ", JSONBigInt.stringify(ecpointJson));

        // p1 step2
        const p1Step2Res = p1Step2(JSONBigInt.stringify(proofJson), JSONBigInt.stringify(ecpointJson));
        console.log(`p1Step2: ${p1Step2Res}`);

        const p1Step2ResJSON = JSONBigInt.parse(p1Step2Res)
        let p1ProofJson = p1Step2ResJSON["data"]["SchnorrProofOutput"]
        parseNumbers(p1ProofJson)
        console.log("p1Step2Res p1ProofJson: ", JSONBigInt.stringify(p1ProofJson));

        let cmtDJson = p1Step2ResJSON["data"]["Witness"]
        parseNumbers(cmtDJson)
        console.log("p1Step2Res cmtDJson: ", JSONBigInt.stringify(cmtDJson));

        // p2 step2
        let p2Step2Result = await request("http://127.0.0.1:8080/api/v1/p2-step2", "POST", {
            "user_name": "zhangsan",
            "cmt_d": cmtDJson,
            "p1_proof": p1ProofJson,
        })
        console.log("p2Step2Result: ", p2Step2Result);

        // p1 step3
        const p1Step3Res = p1Step3(p2Step2Result);
        console.log(`p1Step2: ${p1Step3Res}`);

        console.log("\n>>> Sign hex string: "+ JSONBigInt.parse(p1Step3Res)["data"]["SignHex"]);

    });

}

// 将JSON中的数字字符串转换为数字
const parseNumbers = (obj) => {
    for (let key in obj) {
        if (typeof obj[key] === 'object') {
            parseNumbers(obj[key]);
        } else if (typeof obj[key] === 'string' && /^\d+$/.test(obj[key])) {
            obj[key] = BigInt(obj[key]).valueOf();
        }
    }
    return obj
};


main();
