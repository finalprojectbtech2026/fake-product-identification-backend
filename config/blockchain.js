require("dotenv").config();
const { ethers } = require("ethers");

const ABI = [
  "function verifySeller(address seller)",
  "function revokeSeller(address seller)",
  "function registerProduct(string productCode, bytes32 cloudHash, bytes32 nfcUidHash)",
  "function transferProduct(string productCode, address to)",
  "function getProduct(string productCode) view returns (bool exists, address manufacturer, address currentOwner, bytes32 cloudHash, bytes32 nfcUidHash)"
];

const rpcUrl = process.env.RPC_URL;
const contractAddress = process.env.CONTRACT_ADDRESS;
const adminPrivateKey = process.env.ADMIN_PRIVATE_KEY;

if (!rpcUrl || !contractAddress || !adminPrivateKey) {
  throw new Error("Missing RPC_URL, CONTRACT_ADDRESS, or ADMIN_PRIVATE_KEY");
}

const provider = new ethers.JsonRpcProvider(rpcUrl);
const wallet = new ethers.Wallet(adminPrivateKey, provider);
const contract = new ethers.Contract(contractAddress, ABI, wallet);

module.exports = { provider, wallet, contract, ethers };