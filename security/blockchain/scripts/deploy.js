import { network } from "hardhat";

/**
 * Deployment script for SecureLogAnchor contract.
 * Deploys the contract, verifies deployment receipt, and logs essential contract details.
 */
export async function main() {
  console.log("Deploying SecureLogAnchor contract...");

  const { ethers } = await network.create();

  const [deployer] = await ethers.getSigners();
  console.log(`Deploying from account: ${deployer.address}`);

  const anchor = await ethers.deployContract("SecureLogAnchor");
  await anchor.waitForDeployment();

  const contractAddress = await anchor.getAddress();
  const deployTx = anchor.deploymentTransaction();

  console.log(`SecureLogAnchor deployed successfully!`);
  console.log(`Contract Address: ${contractAddress}`);
  if (deployTx) {
    console.log(`Transaction Hash: ${deployTx.hash}`);
  }

  return { contractAddress, anchor, deployer };
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
