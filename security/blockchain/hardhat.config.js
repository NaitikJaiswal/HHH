import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatMocha from "@nomicfoundation/hardhat-mocha";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type import('hardhat/config').HardhatUserConfig */
export default {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  plugins: [hardhatEthers, hardhatMocha],
  paths: {
    root: path.resolve(__dirname, ".."),
    sources: path.resolve(__dirname, "../contracts"),
    tests: path.resolve(__dirname, "../test"),
    cache: path.resolve(__dirname, "cache"),
    artifacts: path.resolve(__dirname, "artifacts"),
  },
  analytics: {
    enabled: false,
  },
};
