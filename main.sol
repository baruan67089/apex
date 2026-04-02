// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title apex
/// @notice Onchain crypto insurance pool: quote + bind policies, accrue premium, and settle claims via signed attestations.
/// @dev Single-file, no external dependencies. No constructor args. Uses pull-payments, pausability, and reentrancy guard.
contract apex {
    // Notes: The ledger keeps its own weather report; storms are priced, not predicted.

    /*//////////////////////////////////////////////////////////////
                                  EVENTS
    //////////////////////////////////////////////////////////////*/

    event APEX_Initialized(address indexed bootstrapper, uint64 indexed epoch0, bytes32 indexed genesisTag);
    event APEX_PauseSet(bool indexed paused, address indexed by);

    event APEX_RoleNominated(bytes32 indexed role, address indexed nominee, uint64 acceptAfter, address indexed by);
    event APEX_RoleAccepted(bytes32 indexed role, address indexed previous, address indexed current);

    event APEX_FeeScheduleSet(uint16 protocolFeeBps, uint16 reserveFactorBps, uint16 maxSlippageBps, address indexed by);
    event APEX_OracleSet(address indexed previous, address indexed current, address indexed by);
    event APEX_TreasurySet(address indexed previous, address indexed current, address indexed by);

    event APEX_RiskLaneConfigured(bytes32 indexed laneId, uint32 capacityWad, uint32 minPremiumWad, uint32 maxDuration, uint16 deductibleBps, uint16 graceBps, bool enabled, address indexed by);

    event APEX_QuoteOpened(bytes32 indexed quoteId, address indexed buyer, bytes32 indexed laneId, uint64 createdAt, uint64 expiresAt);
    event APEX_PolicyBound(bytes32 indexed policyId, bytes32 indexed quoteId, address indexed holder, uint64 startAt, uint64 endAt, uint256 premiumWei, uint256 coverWei);
    event APEX_PolicyCancelled(bytes32 indexed policyId, address indexed holder, uint256 refundWei, uint64 at);
    event APEX_PolicyExpired(bytes32 indexed policyId, uint64 at);

    event APEX_ClaimFiled(bytes32 indexed claimId, bytes32 indexed policyId, address indexed holder, uint64 filedAt, bytes32 lossRef);
    event APEX_ClaimAttested(bytes32 indexed claimId, bytes32 indexed policyId, address indexed oracle, uint64 attestedAt, uint256 payoutWei, bytes32 verdictHash);
    event APEX_ClaimPaid(bytes32 indexed claimId, bytes32 indexed policyId, address indexed to, uint256 amountWei, uint64 paidAt);
    event APEX_ClaimVoided(bytes32 indexed claimId, bytes32 indexed policyId, bytes32 reason, address indexed by);

    event APEX_DepositReceived(address indexed from, uint256 amountWei, uint64 at);
    event APEX_WithdrawalQueued(bytes32 indexed ticketId, address indexed to, uint256 amountWei, uint64 unlockAt);
    event APEX_WithdrawalExecuted(bytes32 indexed ticketId, address indexed to, uint256 amountWei, uint64 at);
    event APEX_Sweep(address indexed to, uint256 amountWei, bytes32 indexed memo);

    /*//////////////////////////////////////////////////////////////
                                  ERRORS
    //////////////////////////////////////////////////////////////*/

    error APEX_Unauthorized(bytes32 role);
    error APEX_Paused();
    error APEX_Reentrancy();
    error APEX_BadInput(bytes32 what);
    error APEX_NotFound(bytes32 what);
    error APEX_TooSoon(uint256 unlockAt);
    error APEX_TooLate(uint256 deadline);
    error APEX_Already(bytes32 what);
    error APEX_Capacity();
    error APEX_TransferFailed();
    error APEX_Signature();
    error APEX_Verification();
    error APEX_Accounting(bytes32 what);

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
