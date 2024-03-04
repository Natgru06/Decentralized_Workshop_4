import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
  );

  // Return the generated key pair
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  }
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey("spki", key);
  const base64String = arrayBufferToBase64(exportedKey);
  return base64String;
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key) {
    return null;
  }
  const exportedKey = await webcrypto.subtle.exportKey("pkcs8", key);
  const base64String = arrayBufferToBase64(exportedKey);
  return base64String;
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
      "spki",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
  );
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
  );

  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  const dataBuffer = base64ToArrayBuffer(b64Data);
  const publicKey = await importPubKey(strPublicKey);
  const encryptedDataBuffer = await webcrypto.subtle.encrypt({name: "RSA-OAEP",}, publicKey, dataBuffer);
  const encryptedDataB64 = arrayBufferToBase64(encryptedDataBuffer);
  return encryptedDataB64;
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
// Convert Base64-encoded encrypted data to ArrayBuffer
  const encryptedDataBuffer = base64ToArrayBuffer(data);
  const decryptedDataBuffer = await webcrypto.subtle.decrypt({name: "RSA-OAEP",}, privateKey, encryptedDataBuffer);
  const decryptedDataString = arrayBufferToBase64(decryptedDataBuffer);
  return decryptedDataString;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // Generate a random symmetric key
  const symmetricKey = await webcrypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256, // 256-bit key length
      },
      true,
      ["encrypt", "decrypt"]
  );
  return symmetricKey;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the symmetric key
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);
  // Convert the exported key to a Base64 string
  const base64String = arrayBufferToBase64(exportedKey);
  return base64String;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  const importedKey = await webcrypto.subtle.importKey(
      "raw", // Raw binary data format
      keyBuffer,
      {
        name: "AES-CBC",
        length: 256, // 256-bit key length
      },
      true, // Extractable
      ["encrypt", "decrypt"] // Key usages
  );
  return importedKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encoder = new TextEncoder();
  const dataUint8Array = encoder.encode(data);
  const encryptedDataBuffer = await webcrypto.subtle.encrypt({name: "AES-CBC", iv: iv,}, key, dataUint8Array);
  const encryptedDataWithIV = new Uint8Array(iv.length + encryptedDataBuffer.byteLength);
  encryptedDataWithIV.set(iv);
  encryptedDataWithIV.set(new Uint8Array(encryptedDataBuffer), iv.length);

  // Convert the encrypted data (with IV) to a Base64 string
  const encryptedDataB64 = arrayBufferToBase64(encryptedDataWithIV);

  return encryptedDataB64;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);
  const encryptedDataWithIV = base64ToArrayBuffer(encryptedData);
  const iv = encryptedDataWithIV.slice(0, 16); // Assuming IV length is 16 bytes (AES-128)
  const encryptedDataBuffer = encryptedDataWithIV.slice(16);
  const decryptedDataBuffer = await webcrypto.subtle.decrypt({name: "AES-CBC", iv: iv,}, key, encryptedDataBuffer);
  const decoder = new TextDecoder();
  const decryptedDataString = decoder.decode(decryptedDataBuffer);
  return decryptedDataString;
}
