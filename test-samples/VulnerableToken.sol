// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title VulnerableToken
 * @notice This is a TEST contract with intentional vulnerabilities
 *         for demonstrating the Private Code Reviewer.
 *         DO NOT deploy this contract.
 */
contract VulnerableToken is ERC20, Ownable {
    mapping(address => bool) private _blacklisted;
    address public feeRecipient;
    uint256 public transferFee = 5; // 5%
    bool public paused;

    constructor() ERC20("VulnToken", "VULN") Ownable(msg.sender) {
        feeRecipient = msg.sender;
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }

    // RUG PULL: Owner can mint unlimited tokens
    function mintTokens(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    // RUG PULL: Owner can set fee to 100%, stealing all transfers
    function setTransferFee(uint256 newFee) external onlyOwner {
        transferFee = newFee;
    }

    // RUG PULL: Owner can blacklist anyone from transferring
    function blacklistAddress(address account) external onlyOwner {
        _blacklisted[account] = true;
    }

    // RUG PULL: Owner can pause all transfers
    function pause() external onlyOwner {
        paused = true;
    }

    // BACKDOOR: Owner can drain all ETH from the contract
    function withdrawAll() external onlyOwner {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success);
    }

    // BACKDOOR: Hidden fee sent to owner on every transfer
    function _update(address from, address to, uint256 amount) internal override {
        require(!paused, "Transfers paused");
        require(!_blacklisted[from], "Blacklisted");

        if (from != address(0) && to != address(0) && transferFee > 0) {
            uint256 fee = (amount * transferFee) / 100;
            super._update(from, feeRecipient, fee);
            amount -= fee;
        }

        super._update(from, to, amount);
    }

    // VULNERABILITY: Using tx.origin for auth
    function emergencyTransfer(address to, uint256 amount) external {
        require(tx.origin == owner(), "Not owner");
        _transfer(msg.sender, to, amount);
    }

    // BACKDOOR: Upgradeable target via delegatecall
    address public implementation;

    function setImplementation(address newImpl) external onlyOwner {
        implementation = newImpl;
    }

    function execute(bytes calldata data) external onlyOwner {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    // VULNERABILITY: selfdestruct
    function destroy() external onlyOwner {
        selfdestruct(payable(owner()));
    }

    receive() external payable {}
}
