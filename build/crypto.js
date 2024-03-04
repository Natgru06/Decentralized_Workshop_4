"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.symDecrypt = exports.symEncrypt = exports.importSymKey = exports.exportSymKey = exports.createRandomSymmetricKey = exports.rsaDecrypt = exports.rsaEncrypt = exports.importPrvKey = exports.importPubKey = exports.exportPrvKey = exports.exportPubKey = exports.generateRsaKeyPair = void 0;
const crypto_1 = require("crypto");
// #############
// ### Utils ###
// #############
// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer) {
    return Buffer.from(buffer).toString("base64");
}
// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64) {
    var buff = Buffer.from(base64, "base64");
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}
async function generateRsaKeyPair() {
    const keyPair = await crypto_1.webcrypto.subtle.generateKey({
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
    }, true, ["encrypt", "decrypt"]);
    // Return the generated key pair
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
    };
}
exports.generateRsaKeyPair = generateRsaKeyPair;
// Export a crypto public key to a base64 string format
async function exportPubKey(key) {
    const exportedKey = await crypto_1.webcrypto.subtle.exportKey("spki", key);
    const base64String = arrayBufferToBase64(exportedKey);
    return base64String;
}
exports.exportPubKey = exportPubKey;
// Export a crypto private key to a base64 string format
async function exportPrvKey(key) {
    if (!key) {
        return null;
    }
    const exportedKey = await crypto_1.webcrypto.subtle.exportKey("pkcs8", key);
    const base64String = arrayBufferToBase64(exportedKey);
    return base64String;
}
exports.exportPrvKey = exportPrvKey;
// Import a base64 string public key to its native format
async function importPubKey(strKey) {
    const keyBuffer = base64ToArrayBuffer(strKey);
    const importedKey = await crypto_1.webcrypto.subtle.importKey("spki", keyBuffer, {
        name: "RSA-OAEP",
        hash: "SHA-256",
    }, true, ["encrypt"]);
    return importedKey;
}
exports.importPubKey = importPubKey;
// Import a base64 string private key to its native format
async function importPrvKey(strKey) {
    const keyBuffer = base64ToArrayBuffer(strKey);
    const importedKey = await crypto_1.webcrypto.subtle.importKey("pkcs8", keyBuffer, {
        name: "RSA-OAEP",
        hash: "SHA-256",
    }, true, ["decrypt"]);
    return importedKey;
}
exports.importPrvKey = importPrvKey;
// Encrypt a message using an RSA public key
async function rsaEncrypt(b64Data, strPublicKey) {
    const dataBuffer = base64ToArrayBuffer(b64Data);
    const publicKey = await importPubKey(strPublicKey);
    const encryptedDataBuffer = await crypto_1.webcrypto.subtle.encrypt({ name: "RSA-OAEP", }, publicKey, dataBuffer);
    const encryptedDataB64 = arrayBufferToBase64(encryptedDataBuffer);
    return encryptedDataB64;
}
exports.rsaEncrypt = rsaEncrypt;
// Decrypts a message using an RSA private key
async function rsaDecrypt(data, privateKey) {
    // Convert Base64-encoded encrypted data to ArrayBuffer
    const encryptedDataBuffer = base64ToArrayBuffer(data);
    const decryptedDataBuffer = await crypto_1.webcrypto.subtle.decrypt({ name: "RSA-OAEP", }, privateKey, encryptedDataBuffer);
    const decryptedDataString = arrayBufferToBase64(decryptedDataBuffer);
    return decryptedDataString;
}
exports.rsaDecrypt = rsaDecrypt;
// ######################
// ### Symmetric keys ###
// ######################
// Generates a random symmetric key
async function createRandomSymmetricKey() {
    // Generate a random symmetric key
    const symmetricKey = await crypto_1.webcrypto.subtle.generateKey({
        name: "AES-CBC",
        length: 256, // 256-bit key length
    }, true, ["encrypt", "decrypt"]);
    return symmetricKey;
}
exports.createRandomSymmetricKey = createRandomSymmetricKey;
// Export a crypto symmetric key to a base64 string format
async function exportSymKey(key) {
    // Export the symmetric key
    const exportedKey = await crypto_1.webcrypto.subtle.exportKey("raw", key);
    // Convert the exported key to a Base64 string
    const base64String = arrayBufferToBase64(exportedKey);
    return base64String;
}
exports.exportSymKey = exportSymKey;
// Import a base64 string format to its crypto native format
async function importSymKey(strKey) {
    const keyBuffer = base64ToArrayBuffer(strKey);
    const importedKey = await crypto_1.webcrypto.subtle.importKey("raw", // Raw binary data format
    keyBuffer, {
        name: "AES-CBC",
        length: 256, // 256-bit key length
    }, true, // Extractable
    ["encrypt", "decrypt"] // Key usages
    );
    return importedKey;
}
exports.importSymKey = importSymKey;
// Encrypt a message using a symmetric key
async function symEncrypt(key, data) {
    const iv = crypto_1.webcrypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const dataUint8Array = encoder.encode(data);
    const encryptedDataBuffer = await crypto_1.webcrypto.subtle.encrypt({ name: "AES-CBC", iv: iv, }, key, dataUint8Array);
    const encryptedDataWithIV = new Uint8Array(iv.length + encryptedDataBuffer.byteLength);
    encryptedDataWithIV.set(iv);
    encryptedDataWithIV.set(new Uint8Array(encryptedDataBuffer), iv.length);
    // Convert the encrypted data (with IV) to a Base64 string
    const encryptedDataB64 = arrayBufferToBase64(encryptedDataWithIV);
    return encryptedDataB64;
}
exports.symEncrypt = symEncrypt;
// Decrypt a message using a symmetric key
async function symDecrypt(strKey, encryptedData) {
    const key = await importSymKey(strKey);
    const encryptedDataWithIV = base64ToArrayBuffer(encryptedData);
    const iv = encryptedDataWithIV.slice(0, 16); // Assuming IV length is 16 bytes (AES-128)
    const encryptedDataBuffer = encryptedDataWithIV.slice(16);
    const decryptedDataBuffer = await crypto_1.webcrypto.subtle.decrypt({ name: "AES-CBC", iv: iv, }, key, encryptedDataBuffer);
    const decoder = new TextDecoder();
    const decryptedDataString = decoder.decode(decryptedDataBuffer);
    return decryptedDataString;
}
exports.symDecrypt = symDecrypt;
