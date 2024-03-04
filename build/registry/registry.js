"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.launchRegistry = void 0;
const body_parser_1 = __importDefault(require("body-parser"));
const express_1 = __importDefault(require("express"));
const config_1 = require("../config");
const crypto_1 = require("../crypto");
const registeredNodes = [];
async function launchRegistry() {
    const _registry = (0, express_1.default)();
    _registry.use(express_1.default.json());
    _registry.use(body_parser_1.default.json());
    // TODO implement the status route
    _registry.get("/status", (req, res) => {
        res.send("live");
    });
    _registry.post("/registerNode", async (req, res) => {
        const body = req.body;
        if (!body.nodeId) {
            return res.status(400).json({ error: "Invalid request body" });
        }
        const { publicKey, privateKey } = await (0, crypto_1.generateRsaKeyPair)();
        // Export public key to Base64 string
        const pubKeyBase64 = await (0, crypto_1.exportPubKey)(publicKey);
        // Store node information in the registry
        registeredNodes.push({
            nodeId: body.nodeId,
            pubKey: pubKeyBase64
        });
        return res.status(201).json({ message: "Node registered successfully" });
    });
    _registry.get("/getNodeRegistry", (req, res) => {
        const responseBody = {
            nodes: registeredNodes.map(node => ({
                nodeId: node.nodeId,
                pubKey: node.pubKey
            }))
        };
        res.status(200).json(responseBody);
    });
    const server = _registry.listen(config_1.REGISTRY_PORT, () => {
        console.log(`registry is listening on port ${config_1.REGISTRY_PORT}`);
    });
    return server;
}
exports.launchRegistry = launchRegistry;
