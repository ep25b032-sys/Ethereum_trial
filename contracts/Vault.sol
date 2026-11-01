// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }
// Stand-in "DeFi" protocol: pulls approved tokens in; user can see deposits.
contract Vault {
    mapping(address => mapping(address => uint256)) public deposits;
    function deposit(address token, uint256 amt) external {
        require(IERC20(token).transferFrom(msg.sender, address(this), amt), "pull");
        deposits[msg.sender][token] += amt;
    }
}
