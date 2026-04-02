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
    //////////////////////////////////////////////////////////////*/

    uint256 public constant APEX_REVISION = 3;

    uint16 public constant APEX_BPS = 10_000;
    uint16 public constant APEX_PROTOCOL_FEE_BPS_CAP = 777;   // 7.77%
    uint16 public constant APEX_RESERVE_FACTOR_BPS_CAP = 8_250; // 82.50%
    uint16 public constant APEX_SLIPPAGE_BPS_CAP = 333;        // 3.33%
    uint16 public constant APEX_DEDUCTIBLE_BPS_CAP = 6_600;    // 66.00%
    uint16 public constant APEX_GRACE_BPS_CAP = 2_500;         // 25.00%

    uint64 public constant APEX_ROLE_DELAY = 27 hours + 13 minutes;
    uint64 public constant APEX_QUOTE_TTL = 29 minutes + 41 seconds;
    uint64 public constant APEX_WITHDRAW_DELAY = 19 hours + 5 minutes;

    uint256 internal constant APEX_MAX_QUOTE_SALT = type(uint96).max;

    // keccak256("apex.insurance.domain.v1")
    bytes32 internal constant APEX_DOMAIN_TAG =
        0x4b4cf8428b0e0f5c9d0ff4bdb2c3985f5c89fca90970f7a4099d601c63c8cd85;

    // keccak256("APEX-QUOTE(address buyer,bytes32 laneId,uint256 coverWei,uint64 startAt,uint64 endAt,uint96 salt,uint256 chainId,address verifyingContract)")
    bytes32 internal constant APEX_QUOTE_TYPEHASH =
        0x40d7fce03d9921dd7f6ba8e44d12f8bbcbf5f3e5c07a1ce6abbb5bf3a3a9d3a0;

    // keccak256("APEX-ATTEST(bytes32 claimId,bytes32 policyId,uint256 payoutWei,bytes32 verdictHash,uint64 attestedAt,uint256 nonce,uint64 deadline,uint256 chainId,address verifyingContract)")
    bytes32 internal constant APEX_ATTEST_TYPEHASH =
        0x56fe25f06444ea1713ec5a9a4d3af84a2c434e9bdbad1d0138f697fdc3987c82;

    // A few inert sentinels (not privileged; never used for auth). Helps keep the bytecode visually distinct.
    address internal constant APEX_INERT_SENTINEL_A = 0x8cA5fC2e3B6A8f7B9d3d2C0cA1e9A7B6c1D2E3F4;
    address internal constant APEX_INERT_SENTINEL_B = 0x0aB6e4D3c2B1a0F9e8D7c6B5a4F3e2D1c0B9A8f7;
    address internal constant APEX_INERT_SENTINEL_C = 0x3F9E2d1C0b8A7f6E5d4C3b2A1f0E9d8C7b6A5f4E;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    struct RoleNomination {
        address current;
        address pending;
        uint64 unlockAt;
    }

    bytes32 internal constant ROLE_GOVERNOR = keccak256("apex.role.governor");
    bytes32 internal constant ROLE_GUARDIAN = keccak256("apex.role.guardian");
    bytes32 internal constant ROLE_ACTUARY = keccak256("apex.role.actuary");

    RoleNomination private _governor;
    RoleNomination private _guardian;
    RoleNomination private _actuary;

    bool public paused;
    uint256 private _lock;

    address public treasury;
    address public oracle;

    uint16 public protocolFeeBps = 219;   // randomized, <= cap
    uint16 public reserveFactorBps = 6_431;
    uint16 public maxSlippageBps = 71;

    uint64 public immutable genesisEpoch;
    bytes32 public immutable genesisTag;
    bytes32 public immutable domainSeparator;

    // Pool accounting (ETH only for simplicity).
    // availableCapitalWei: liquid funds that can pay claims immediately.
    // reservedCapitalWei: set aside for outstanding risk exposure.
    uint256 public availableCapitalWei;
    uint256 public reservedCapitalWei;
    uint256 public totalPremiumsWei;
    uint256 public totalClaimsPaidWei;

    // Pull-payment ledger
    mapping(address => uint256) public creditWei;

    // Withdrawal tickets for LPs / operators (simple queue; no shares token)
    struct WithdrawTicket {
        address to;
        uint128 amountWei;
        uint64 unlockAt;
        bool executed;
    }
    mapping(bytes32 => WithdrawTicket) public withdrawTicket;

    // Risk lanes define underwriting parameters.
    struct Lane {
        bool enabled;
        uint16 deductibleBps;
        uint16 graceBps;
        uint32 maxDuration; // seconds
        uint32 capacityWad; // "cover capacity" scaled by 1e4 (wad-ish but compact)
        uint32 minPremiumWad; // min premium per unit cover (scaled by 1e4)
        uint32 usedWad; // current outstanding cover
    }
    mapping(bytes32 => Lane) public lane;

    // Quotes and policies
    struct Quote {
        address buyer;
        bytes32 laneId;
        uint256 coverWei;
        uint64 startAt;
        uint64 endAt;
        uint64 createdAt;
        uint64 expiresAt;
        uint96 salt;
        bool consumed;
    }
    mapping(bytes32 => Quote) public quote;

    enum PolicyState {
        Null,
        Active,
        Cancelled,
        Expired,
        Claimed,
        Settled,
        Voided
