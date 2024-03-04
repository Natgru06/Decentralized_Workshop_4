import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";
import {
  generateRsaKeyPair,
  exportPubKey,
  exportPrvKey,
  importPrvKey
} from "../crypto";
export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: RegisterNodeBody[] = [];
export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // TODO implement the status route
   _registry.get("/status", (req, res) => {
     res.send("live");
   });

  _registry.post("/registerNode", async (req: Request, res: Response) => {
    const body: RegisterNodeBody = req.body;

    if (!body.nodeId) {
      return res.status(400).json({ error: "Invalid request body" });
    }
    const { publicKey, privateKey } = await generateRsaKeyPair();

    // Export public key to Base64 string
    const pubKeyBase64 = await exportPubKey(publicKey);

    // Store node information in the registry
    registeredNodes.push({
      nodeId: body.nodeId,
      pubKey: pubKeyBase64
    });

    return res.status(201).json({ message: "Node registered successfully" });

  });

  _registry.get("/getNodeRegistry", (req, res) => {
    const responseBody: GetNodeRegistryBody = {
      nodes: registeredNodes.map(node => ({
        nodeId: node.nodeId,
        pubKey: node.pubKey
      }))
    };
    res.status(200).json(responseBody);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
