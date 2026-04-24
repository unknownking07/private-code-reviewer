// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// TEST contract with intentional vulnerabilities. DO NOT deploy.
// Covers a different class of issues than VulnerableToken.sol:
// reentrancy, oracle manipulation, unchecked external calls, DoS,
// and uninitialized proxies.

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract VulnerableStaking {
    IERC20 public stakingToken;
    IERC20 public rewardToken;
    IPriceOracle public oracle;
    address public admin;

    mapping(address => uint256) public balances;
    address[] public stakers;
    uint256 public totalStaked;
    uint256 public rewardRate = 100; // basis points

    // VULN: no initializer guard — can be called again by anyone
    function initialize(address _staking, address _reward, address _oracle) external {
        stakingToken = IERC20(_staking);
        rewardToken = IERC20(_reward);
        oracle = IPriceOracle(_oracle);
        admin = msg.sender;
    }

    function stake(uint256 amount) external {
        stakingToken.transferFrom(msg.sender, address(this), amount); // VULN: unchecked return
        if (balances[msg.sender] == 0) stakers.push(msg.sender);
        balances[msg.sender] += amount;
        totalStaked += amount;
    }

    // VULN: classic reentrancy — external call before state update
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: 0}(
            abi.encodeWithSignature("onWithdraw(uint256)", amount)
        );
        require(ok, "hook failed");
        stakingToken.transfer(msg.sender, amount);
        balances[msg.sender] -= amount;
        totalStaked -= amount;
    }

    // VULN: oracle manipulation — price derived from pool balance, flash-loan exploitable
    function currentPrice() public view returns (uint256) {
        uint256 bal = stakingToken.balanceOf(address(this));
        if (bal == 0) return 0;
        return (rewardToken.balanceOf(address(this)) * 1e18) / bal;
    }

    // VULN: rewards scale with oracle → attacker inflates payout then withdraws
    function claimRewards() external {
        uint256 userBal = balances[msg.sender];
        uint256 price = currentPrice();
        uint256 reward = (userBal * rewardRate * price) / (10_000 * 1e18);
        rewardToken.transfer(msg.sender, reward); // VULN: unchecked return
    }

    // VULN: O(n) loop over unbounded stakers — DoS at scale
    function distributeBonus(uint256 bonusPool) external {
        require(msg.sender == admin);
        for (uint256 i = 0; i < stakers.length; i++) {
            uint256 share = (balances[stakers[i]] * bonusPool) / totalStaked;
            rewardToken.transfer(stakers[i], share);
        }
    }

    // VULN: no access control — anyone can change rate
    function setRewardRate(uint256 newRate) external {
        rewardRate = newRate;
    }

    // VULN: admin can pull any token (rug)
    function sweep(address token, uint256 amount) external {
        require(msg.sender == admin);
        IERC20(token).transfer(admin, amount);
    }

    // VULN: arbitrary delegatecall backdoor
    function exec(address target, bytes calldata data) external {
        require(msg.sender == admin);
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
}
