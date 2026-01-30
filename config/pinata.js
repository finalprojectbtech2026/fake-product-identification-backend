const axios = require("axios");
const FormData = require("form-data");

function getGatewayBase() {
  return process.env.PINATA_GATEWAY_BASE || "https://gateway.pinata.cloud/ipfs/";
}

async function pinFileToIPFS({ fileBuffer, filename, mimeType }) {
  const jwt = String(process.env.PINATA_JWT || "").trim();
  if (!jwt) throw new Error("Missing PINATA_JWT");

  const form = new FormData();
  form.append("file", fileBuffer, { filename: filename || "file", contentType: mimeType || "application/octet-stream" });

  const resp = await axios.post("https://api.pinata.cloud/pinning/pinFileToIPFS", form, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      ...form.getHeaders()
    },
    maxBodyLength: Infinity
  });

  const cid = resp?.data?.IpfsHash;
  if (!cid) throw new Error("Pinata upload failed");

  return {
    ipfs_cid: cid,
    ipfs_url: `${getGatewayBase()}${cid}`
  };
}

module.exports = { pinFileToIPFS };