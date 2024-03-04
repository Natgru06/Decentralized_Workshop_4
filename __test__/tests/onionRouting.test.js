"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../../src/config");
const index_1 = require("../../src/index");
const crypto_1 = require("../../src/crypto");
const { validateEncryption } = require("./utils");
const delay = (ms) => new Promise((res) => setTimeout(res, ms));
function closeAllServers(servers) {
    return __awaiter(this, void 0, void 0, function* () {
        yield Promise.all(servers.map((server) => server.close(() => {
            server.closeAllConnections();
        })));
        yield delay(100);
    });
}
function sendMessage(userPort, message, destinationUserId) {
    return __awaiter(this, void 0, void 0, function* () {
        yield fetch(`http://localhost:${userPort}/sendMessage`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                message,
                destinationUserId,
            }),
        });
    });
}
function getLastMessageDestination(nodePort) {
    return __awaiter(this, void 0, void 0, function* () {
        const lastMessageDestination = yield fetch(`http://localhost:${nodePort}/getLastMessageDestination`)
            .then((res) => res.json())
            .then((json) => json === null || json === void 0 ? void 0 : json.result);
        return lastMessageDestination;
    });
}
function getLastReceivedEncryptedMessage(nodePort) {
    return __awaiter(this, void 0, void 0, function* () {
        const lastReceivedEncryptedMessage = yield fetch(`http://localhost:${nodePort}/getLastReceivedEncryptedMessage`)
            .then((res) => res.json())
            .then((json) => json === null || json === void 0 ? void 0 : json.result);
        return lastReceivedEncryptedMessage;
    });
}
function getLastReceivedDecryptedMessage(nodePort) {
    return __awaiter(this, void 0, void 0, function* () {
        const lastReceivedDecryptedMessage = yield fetch(`http://localhost:${nodePort}/getLastReceivedDecryptedMessage`)
            .then((res) => res.json())
            .then((json) => json === null || json === void 0 ? void 0 : json.result);
        return lastReceivedDecryptedMessage;
    });
}
function getPrivateKey(nodePort) {
    return __awaiter(this, void 0, void 0, function* () {
        const strPrvKey = yield fetch(`http://localhost:${nodePort}/getPrivateKey`)
            .then((res) => res.json())
            .then((json) => json.result);
        return strPrvKey;
    });
}
function getLastSentMessage(userPort) {
    return __awaiter(this, void 0, void 0, function* () {
        const lastSentMessage = yield fetch(`http://localhost:${userPort}/getLastSentMessage`)
            .then((res) => res.json())
            .then((json) => json === null || json === void 0 ? void 0 : json.result);
        return lastSentMessage;
    });
}
function getLastReceivedMessage(userPort) {
    return __awaiter(this, void 0, void 0, function* () {
        const lastReceivedMessage = yield fetch(`http://localhost:${userPort}/getLastReceivedMessage`)
            .then((res) => res.json())
            .then((json) => json === null || json === void 0 ? void 0 : json.result);
        return lastReceivedMessage;
    });
}
function getLastCircuit(userPort) {
    return __awaiter(this, void 0, void 0, function* () {
        const circuit = yield fetch(`http://localhost:${userPort}/getLastCircuit`)
            .then((res) => res.json())
            .then((json) => json.result);
        return circuit;
    });
}
function getNodeRegistry() {
    return __awaiter(this, void 0, void 0, function* () {
        const nodes = yield fetch(`http://localhost:${config_1.REGISTRY_PORT}/getNodeRegistry`)
            .then((res) => res.json())
            .then((json) => json.nodes);
        return nodes;
    });
}
describe("Onion Routing", () => {
    describe("Project is setup correctly - 4 pt", () => {
        describe("Can start a specific number of nodes and users - 1 pt", () => {
            let servers = [];
            afterEach(() => __awaiter(void 0, void 0, void 0, function* () {
                yield closeAllServers(servers);
            }));
            it("Can start 1 node and 1 user", () => __awaiter(void 0, void 0, void 0, function* () {
                servers = yield (0, index_1.launchNetwork)(1, 1);
                const isNodeLive = yield fetch(`http://localhost:${config_1.BASE_ONION_ROUTER_PORT + 0}/status`)
                    .then((res) => res.text())
                    .then((text) => text === "live");
                expect(isNodeLive).toBeTruthy();
                const isUserLive = yield fetch(`http://localhost:${config_1.BASE_USER_PORT + 0}/status`)
                    .then((res) => res.text())
                    .then((text) => text === "live");
                expect(isUserLive).toBeTruthy();
            }));
            it("Can start 10 node and 2 user", () => __awaiter(void 0, void 0, void 0, function* () {
                servers = yield (0, index_1.launchNetwork)(10, 2);
                for (let index = 0; index < 10; index++) {
                    const isNodeLive = yield fetch(`http://localhost:${config_1.BASE_ONION_ROUTER_PORT + index}/status`)
                        .then((res) => res.text())
                        .then((text) => text === "live");
                    expect(isNodeLive).toBeTruthy();
                }
                for (let index = 0; index < 2; index++) {
                    const isUserLive = yield fetch(`http://localhost:${config_1.BASE_USER_PORT + index}/status`)
                        .then((res) => res.text())
                        .then((text) => text === "live");
                    expect(isUserLive).toBeTruthy();
                }
            }));
            it("Can start 2 node and 10 user", () => __awaiter(void 0, void 0, void 0, function* () {
                servers = yield (0, index_1.launchNetwork)(2, 10);
                for (let index = 0; index < 2; index++) {
                    const isNodeLive = yield fetch(`http://localhost:${config_1.BASE_ONION_ROUTER_PORT + index}/status`)
                        .then((res) => res.text())
                        .then((text) => text === "live");
                    expect(isNodeLive).toBeTruthy();
                }
                for (let index = 0; index < 10; index++) {
                    const isUserLive = yield fetch(`http://localhost:${config_1.BASE_USER_PORT + index}/status`)
                        .then((res) => res.text())
                        .then((text) => text === "live");
                    expect(isUserLive).toBeTruthy();
                }
            }));
            it("The registry exists", () => __awaiter(void 0, void 0, void 0, function* () {
                servers = yield (0, index_1.launchNetwork)(2, 10);
                const isRegistryLive = yield fetch(`http://localhost:${config_1.REGISTRY_PORT}/status`)
                    .then((res) => res.text())
                    .then((text) => text === "live");
                expect(isRegistryLive).toBeTruthy();
            }));
        });
        describe("Define simple GET routes - 1 pt", () => {
            const servers = [];
            beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
                const _servers = yield (0, index_1.launchNetwork)(10, 2);
                servers.push(..._servers);
            }));
            afterAll(() => __awaiter(void 0, void 0, void 0, function* () {
                yield closeAllServers(servers);
            }));
            it("calling /getLastReceivedEncryptedMessage on a node before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastReceivedEncryptedMessage
                const lastReceivedEncryptedMessage = yield getLastReceivedEncryptedMessage(config_1.BASE_ONION_ROUTER_PORT + 0);
                expect(lastReceivedEncryptedMessage).toBeNull();
            }));
            it("calling /getLastReceivedDecryptedMessage on a node before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastReceivedDecryptedMessage
                const lastReceivedDecryptedMessage = yield getLastReceivedDecryptedMessage(config_1.BASE_ONION_ROUTER_PORT + 9);
                expect(lastReceivedDecryptedMessage).toBeNull();
            }));
            it("calling /getLastMessageDestination on a node before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastMessageDestination
                const lastMessageDestination = yield getLastMessageDestination(config_1.BASE_ONION_ROUTER_PORT + 3);
                expect(lastMessageDestination).toBeNull();
            }));
            it("calling /getLastMessageDestination on a node before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastMessageDestination
                const lastMessageDestination = yield getLastMessageDestination(config_1.BASE_ONION_ROUTER_PORT + 1);
                expect(lastMessageDestination).toBeNull();
            }));
            it("calling /getLastReceivedMessage on a user before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastReceivedMessage
                const lastReceivedMessage = yield getLastReceivedMessage(config_1.BASE_USER_PORT + 1);
                expect(lastReceivedMessage).toBeNull();
            }));
            it("calling /getLastSentMessage on a user before it received anything returns { result: null }", () => __awaiter(void 0, void 0, void 0, function* () {
                // getLastSentMessage
                const lastSentMessage = yield getLastSentMessage(config_1.BASE_USER_PORT + 0);
                expect(lastSentMessage).toBeNull();
            }));
        });
        describe("Nodes are registered on the registry - 1 pt", () => {
            const servers = [];
            beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
                const _servers = yield (0, index_1.launchNetwork)(10, 2);
                servers.push(..._servers);
            }));
            afterAll(() => __awaiter(void 0, void 0, void 0, function* () {
                yield closeAllServers(servers);
            }));
            it("Each node is registered", () => __awaiter(void 0, void 0, void 0, function* () {
                const nodes = yield getNodeRegistry();
                for (let index = 0; index < 10; index++) {
                    const node = nodes.find((_n) => _n.nodeId === index);
                    expect(node).not.toBeUndefined();
                }
            }));
            it("Each node has a public key in the right format", () => __awaiter(void 0, void 0, void 0, function* () {
                const nodes = yield getNodeRegistry();
                expect(nodes.length).toBe(10);
                for (let index = 0; index < 10; index++) {
                    const node = nodes.find((_n) => _n.nodeId === index);
                    expect(node !== undefined && /^[A-Za-z0-9+/]{392}$/.test(node.pubKey)).toBeTruthy();
                }
            }));
            it("All public keys are different", () => __awaiter(void 0, void 0, void 0, function* () {
                const nodes = yield getNodeRegistry();
                const pubKeys = new Set();
                for (let index = 0; index < nodes.length; index++) {
                    pubKeys.add(nodes[index].pubKey);
                }
                expect(pubKeys.size).toBe(10);
            }));
            it("Can get the private key of any node through the /getPrivateKey route", () => __awaiter(void 0, void 0, void 0, function* () {
                const nodes = yield getNodeRegistry();
                for (let index = 0; index < nodes.length; index++) {
                    const node = nodes[index];
                    const strPrvKey = yield getPrivateKey(config_1.BASE_ONION_ROUTER_PORT + node.nodeId);
                    expect(/^[-A-Za-z0-9+/]*={0,3}$/.test(strPrvKey)).toBeTruthy();
                    const prvKey = yield (0, crypto_1.importPrvKey)(strPrvKey);
                    const b64Message = btoa("hello world");
                    const encrypted = yield (0, crypto_1.rsaEncrypt)(b64Message, node.pubKey);
                    const decrypted = yield (0, crypto_1.rsaDecrypt)(encrypted, prvKey);
                    // verify that the retrieved private key corresponds to the public key in the registry
                    expect(decrypted).toBe(b64Message);
                }
            }));
        });
        describe("Sending messages to users - 1 pt", () => {
            const servers = [];
            beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
                const _servers = yield (0, index_1.launchNetwork)(10, 2);
                servers.push(..._servers);
            }));
            afterAll(() => __awaiter(void 0, void 0, void 0, function* () {
                yield closeAllServers(servers);
            }));
            it("Each user can receive a message", () => __awaiter(void 0, void 0, void 0, function* () {
                for (let index = 0; index < 2; index++) {
                    const response = yield fetch(`http://localhost:${config_1.BASE_USER_PORT + index}/message`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                        },
                        body: JSON.stringify({
                            message: "Hello user",
                        }),
                    }).then((res) => res.text());
                    expect(response).toBe("success");
                }
            }));
            it("After receiving a message, a user's /getLastReceivedMessage route returns the right message", () => __awaiter(void 0, void 0, void 0, function* () {
                const randomNumber = crypto
                    .getRandomValues(new Uint32Array(1))[0]
                    .toString();
                const randomMessage = `Hello user, my favourite number is ${randomNumber}`;
                yield fetch(`http://localhost:${config_1.BASE_USER_PORT + 0}/message`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({
                        message: randomMessage,
                    }),
                });
                const receivedMessage = yield getLastReceivedMessage(config_1.BASE_USER_PORT + 0);
                expect(receivedMessage).toBe(randomMessage);
            }));
        });
    });
    describe("Creating all cryptographic functions - 4pt", () => {
        it("Can generate RSA key pair - 0.5pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const { publicKey, privateKey } = yield (0, crypto_1.generateRsaKeyPair)();
            expect(publicKey).toBeTruthy();
            expect(publicKey.algorithm.name).toBe("RSA-OAEP");
            expect(privateKey.algorithm.name).toBe("RSA-OAEP");
            expect(publicKey.extractable).toBe(true);
            expect(privateKey.extractable).toBe(true);
            expect(publicKey.type).toBe("public");
            expect(privateKey.type).toBe("private");
        }));
        it("Can export and import a public key - 0.25pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const { publicKey } = yield (0, crypto_1.generateRsaKeyPair)();
            const strPubKey = yield (0, crypto_1.exportPubKey)(publicKey);
            const _publicKey = yield (0, crypto_1.importPubKey)(strPubKey);
            const _strPubKey = yield (0, crypto_1.exportPubKey)(_publicKey);
            expect(strPubKey).toBe(_strPubKey);
            expect(strPubKey).not.toBe("");
        }));
        it("Can export and import a private key - 0.25pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const { privateKey } = yield (0, crypto_1.generateRsaKeyPair)();
            const strPrvKey = yield (0, crypto_1.exportPrvKey)(privateKey);
            if (strPrvKey === null)
                throw new Error("strPrvKey is null");
            const _privateKey = yield (0, crypto_1.importPrvKey)(strPrvKey);
            const _strPrvKey = yield (0, crypto_1.exportPrvKey)(_privateKey);
            expect(strPrvKey).toBe(_strPrvKey);
            expect(strPrvKey).not.toBe("");
        }));
        it("Can rsa encrypt and decrypt - 0pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const { publicKey, privateKey } = yield (0, crypto_1.generateRsaKeyPair)();
            const b64Message = btoa("Hello World!!");
            const encrypted = yield (0, crypto_1.rsaEncrypt)(b64Message, yield (0, crypto_1.exportPubKey)(publicKey));
            const decrypted = yield (0, crypto_1.rsaDecrypt)(encrypted, privateKey);
            // verify that the retrieved private key corresponds to the public key in the registry
            expect(decrypted).toBe(b64Message);
        }));
        test.todo("Hidden test - Can rsa encrypt and decrypt - 1pt");
        it("Can generate symmetric key - 0.5 pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const symKey = yield (0, crypto_1.createRandomSymmetricKey)();
            expect(symKey).toBeTruthy();
            expect(symKey.algorithm.name).toBe("AES-CBC");
            expect(symKey.extractable).toBe(true);
            expect(symKey.type).toBe("secret");
        }));
        it("Can export and import a symmetric key - 0.5pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const symKey = yield (0, crypto_1.createRandomSymmetricKey)();
            const strSymKey = yield (0, crypto_1.exportSymKey)(symKey);
            const _symKey = yield (0, crypto_1.importSymKey)(strSymKey);
            const _strSymKey = yield (0, crypto_1.exportSymKey)(_symKey);
            expect(strSymKey).toBe(_strSymKey);
            expect(strSymKey).not.toBe("");
        }));
        it("Can symmetrically encrypt and decrypt - 0pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const symKey = yield (0, crypto_1.createRandomSymmetricKey)();
            const b64Message = btoa("HelloWorld");
            const encrypted = yield (0, crypto_1.symEncrypt)(symKey, b64Message);
            const decrypted = yield (0, crypto_1.symDecrypt)(yield (0, crypto_1.exportSymKey)(symKey), encrypted);
            // verify that the retrieved private key corresponds to the public key in the registry
            expect(decrypted).toBe(b64Message);
        }));
        test.todo("Hidden test - Can symmetrically encrypt and decrypt - 1pt");
    });
    describe("Can forward messages through the network - 10 pt", () => {
        const servers = [];
        beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
            const _servers = yield (0, index_1.launchNetwork)(10, 2);
            servers.push(..._servers);
        }));
        afterAll(() => __awaiter(void 0, void 0, void 0, function* () {
            yield closeAllServers(servers);
        }));
        it("User 0 can say Hello World! to user 1 - 4 pt", () => __awaiter(void 0, void 0, void 0, function* () {
            yield sendMessage(config_1.BASE_USER_PORT + 0, "Hello World!", 1);
            const receivedMessage = yield getLastReceivedMessage(config_1.BASE_USER_PORT + 1);
            expect(receivedMessage).toBe("Hello World!");
            const lastSentMessage = yield getLastSentMessage(config_1.BASE_USER_PORT + 0);
            expect(lastSentMessage).toBe("Hello World!");
        }));
        it("The circuit from 0 to 1 is respected - 1 pt", () => __awaiter(void 0, void 0, void 0, function* () {
            const callNumbers = new Array(10).fill(0);
            // This will be increased when grading exercises
            for (let index = 0; index < 150; index++) {
                yield sendMessage(config_1.BASE_USER_PORT + 0, "Hello World", 1);
                const circuit = yield getLastCircuit(config_1.BASE_USER_PORT + 0);
                expect(circuit).not.toBeUndefined();
                // circuit has 3 nodes
                expect(circuit.length).toBe(3);
                // nodes are unique
                expect(new Set(circuit).size).toBe(3);
                for (let index = 0; index < circuit.length; index++) {
                    callNumbers[circuit[index]] += 1;
                    expect(typeof circuit[index]).toBe("number");
                }
                // all nodes exist
                expect(Math.max(...circuit)).toBeLessThanOrEqual(9);
                expect(Math.min(...circuit)).toBeGreaterThanOrEqual(0);
            }
            const sum = callNumbers.reduce((acc, val) => acc + val, 0);
            const frequencies = callNumbers.map((val) => val / sum);
            // each node has more or less 10% occurence
            for (let index = 0; index < frequencies.length; index++) {
                const freq = frequencies[index];
                expect(freq).toBeGreaterThanOrEqual(0.05);
                expect(freq).toBeLessThanOrEqual(0.15);
            }
        }));
        it("Each node in the circuit forwarded the message to the right node - 2pt", () => __awaiter(void 0, void 0, void 0, function* () {
            yield sendMessage(config_1.BASE_USER_PORT + 0, "Hello world", 1);
            const circuit = yield getLastCircuit(config_1.BASE_USER_PORT + 0);
            let lastDecrypted;
            for (let index = 0; index < circuit.length - 1; index++) {
                const nextDestination = yield getLastMessageDestination(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                const actualNextDestination = config_1.BASE_ONION_ROUTER_PORT + circuit[index + 1];
                expect(nextDestination).toBe(actualNextDestination);
                const lastReceivedEncryptedMessage = yield getLastReceivedEncryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                if (lastDecrypted) {
                    expect(lastReceivedEncryptedMessage).toBe(lastDecrypted);
                }
                expect(lastReceivedEncryptedMessage !== null &&
                    /^[A-Za-z0-9+/=]*$/.test(lastReceivedEncryptedMessage)).toBeTruthy();
                const lastReceivedDecryptedMessage = yield getLastReceivedDecryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                lastDecrypted = lastReceivedDecryptedMessage;
                expect(lastReceivedDecryptedMessage !== null &&
                    /^[A-Za-z0-9+/=]*$/.test(lastReceivedDecryptedMessage)).toBeTruthy();
            }
            // last node
            {
                const lastDestination = yield getLastMessageDestination(config_1.BASE_ONION_ROUTER_PORT + circuit[circuit.length - 1]);
                const actualLastDestination = config_1.BASE_USER_PORT + 1;
                expect(lastDestination).toBe(actualLastDestination);
                const lastReceivedEncryptedMessage = yield getLastReceivedEncryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[circuit.length - 1]);
                expect(lastReceivedEncryptedMessage !== null &&
                    /^[A-Za-z0-9+/=]*$/.test(lastReceivedEncryptedMessage)).toBeTruthy();
                const lastReceivedDecryptedMessage = yield getLastReceivedDecryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[circuit.length - 1]);
                expect(lastReceivedDecryptedMessage).toBe("Hello world");
            }
            const receivedMessage = yield getLastReceivedMessage(config_1.BASE_USER_PORT + 1);
            expect(receivedMessage).toBe("Hello world");
        }));
        it("The right message is passed to each node - 1pt", () => __awaiter(void 0, void 0, void 0, function* () {
            yield sendMessage(config_1.BASE_USER_PORT + 0, "We are finally testing the whole decentralised network !", 1);
            const circuit = yield getLastCircuit(config_1.BASE_USER_PORT + 0);
            for (let index = 0; index < circuit.length - 1; index++) {
                const lastReceivedEncryptedMessage = yield getLastReceivedEncryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                const lastReceivedDecryptedMessage = yield getLastReceivedDecryptedMessage(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                const privateKey = yield getPrivateKey(config_1.BASE_ONION_ROUTER_PORT + circuit[index]);
                const isValid = yield validateEncryption(lastReceivedEncryptedMessage, lastReceivedDecryptedMessage, privateKey);
                expect(isValid).toBeTruthy();
            }
        }));
        test.todo("Hidden test - the right message is passed to each node - 2pt");
    });
    describe("Hidden tests - 2 pt", () => {
        const servers = [];
        beforeAll(() => __awaiter(void 0, void 0, void 0, function* () {
            const _servers = yield (0, index_1.launchNetwork)(10, 2);
            servers.push(..._servers);
        }));
        afterAll(() => __awaiter(void 0, void 0, void 0, function* () {
            yield closeAllServers(servers);
        }));
        test.todo("Hidden test - Can send an empty message - 1pt");
        test.todo("Hidden test - Edge case #2 - 1pt");
    });
});
