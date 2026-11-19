// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title PTVSClaimInjectorV2
 * @author Aurelio Tamarit Blay — PropTrust Association (Zug, CH)
 * @notice Normative On-Chain Oracle & Physical-State Risk Engine for PTVS v2.0 (RFC-004 to RFC-007).
 * @dev Bridges Google Cloud Confidential Space (AMD SEV-SNP / KMS HSM) attestations with ERC-3643 RWA tokens.
 */
contract PTVSClaimInjectorV2 is AccessControl {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    bytes32 public constant TEE_ORACLE_SIGNER_ROLE = keccak256("TEE_ORACLE_SIGNER_ROLE");

    uint16 public constant MAX_BPS = 10000; // 100.00%
    uint16 public criticalIntegrityThresholdBps = 7500; // 75.00% minimum physical integrity

    enum AssetLifecycleState {
        HOLLOW_UNVERIFIED,   // RFC-003: Token minted but locked pending QFER
        ACTIVE_VERIFIED,     // Physical & legal integrity verified
        DEGRADED_HAIRCUT,    // Ifis < threshold: dynamic collateral haircut enforced
        FROZEN_REMEDIATION   // Severe physical anomaly: transfers/pledges suspended
    }

    struct PhysicalStateRecord {
        bytes32 qferRootHash;           // SHA-256 root of the QFER dossier
        bytes32 teeEnclaveMeasurement;  // AMD SEV-SNP / Intel TDX container image digest
        bytes32 zkSolvencyNullifier;    // RFC-006: ZK-SNARK proof commitment (no PII exposed)
        uint16 integrityIndexBps;       // RFC-007: Ifis (0 to 10000 bps)
        uint16 dynamicHaircutBps;       // RFC-007: Automated Basel III collateral haircut
        uint64 lastTelemetrySync;       // Timestamp of last InSAR / Edge-AI attestation
        uint8 completedMilestones;      // Parametric escrow milestone counter
        AssetLifecycleState state;
    }

    /// @notice Maps an ERC-3643 token address (or asset ID) to its live physical state
    mapping(address => PhysicalStateRecord) private _assetStates;

    /// @notice Replay protection nonce per asset
    mapping(address => uint256) public assetNonces;

    event QFERStateInjected(
        address indexed rwaToken,
        bytes32 indexed qferRootHash,
        uint16 integrityIndexBps,
        uint16 dynamicHaircutBps,
        AssetLifecycleState newState,
        uint256 nonce
    );

    event ZKSolvencyProofRecorded(
        address indexed rwaToken,
        bytes32 indexed zkSolvencyNullifier,
        uint64 timestamp
    );

    event EscrowMilestoneUnlocked(
        address indexed rwaToken,
        uint8 milestoneId,
        bytes32 evidenceHash
    );

    error InvalidTEEAttestationSignature();
    error InvalidIntegrityScore();
    error AssetNotActiveOrFrozen();

    constructor(address initialAdmin, address kmsHsmOracleAddress) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(GOVERNANCE_ROLE, initialAdmin);
        _grantRole(TEE_ORACLE_SIGNER_ROLE, kmsHsmOracleAddress);
    }

    /**
     * @notice Injects a hardware-attested QFER state update from Google Cloud Confidential Space.
     * @param rwaToken Address of the ERC-3643 compliant RWA token.
     * @param qferRootHash SHA-256 hash of the Qualified Forensic Evidence Record.
     * @param teeEnclaveMeasurement Expected measurement digest of the AMD SEV-SNP enclave.
     * @param zkSolvencyNullifier Commitment hash of the RFC-006 ZK-SNARK solvency proof.
     * @param integrityIndexBps Physical Integrity Index (Ifis) in basis points (0 - 10000).
     * @param milestoneId Current verified construction/rehabilitation milestone (0 if operational).
     * @param hsmSignature ECDSA signature generated inside Google Cloud KMS FIPS 140-3 HSM.
     */
    function injectPhysicalState(
        address rwaToken,
        bytes32 qferRootHash,
        bytes32 teeEnclaveMeasurement,
        bytes32 zkSolvencyNullifier,
        uint16 integrityIndexBps,
        uint8 milestoneId,
        bytes calldata hsmSignature
    ) external {
        if (integrityIndexBps > MAX_BPS) revert InvalidIntegrityScore();

        uint256 currentNonce = assetNonces[rwaToken];

        bytes32 digest = keccak256(
            abi.encodePacked(
                block.chainid,
                address(this),
                rwaToken,
                qferRootHash,
                teeEnclaveMeasurement,
                zkSolvencyNullifier,
                integrityIndexBps,
                milestoneId,
                currentNonce
            )
        ).toEthSignedMessageHash();

        address recoveredSigner = digest.recover(hsmSignature);
        if (!hasRole(TEE_ORACLE_SIGNER_ROLE, recoveredSigner)) {
            revert InvalidTEEAttestationSignature();
        }

        assetNonces[rwaToken] = currentNonce + 1;

        (AssetLifecycleState computedState, uint16 computedHaircut) = _evaluateRiskParameters(
            integrityIndexBps
        );

        PhysicalStateRecord storage record = _assetStates[rwaToken];
        record.qferRootHash = qferRootHash;
        record.teeEnclaveMeasurement = teeEnclaveMeasurement;
        record.zkSolvencyNullifier = zkSolvencyNullifier;
        record.integrityIndexBps = integrityIndexBps;
        record.dynamicHaircutBps = computedHaircut;
        record.lastTelemetrySync = uint64(block.timestamp);
        record.state = computedState;

        if (milestoneId > record.completedMilestones) {
            record.completedMilestones = milestoneId;
            emit EscrowMilestoneUnlocked(rwaToken, milestoneId, qferRootHash);
        }

        if (zkSolvencyNullifier != bytes32(0)) {
            emit ZKSolvencyProofRecorded(rwaToken, zkSolvencyNullifier, uint64(block.timestamp));
        }

        emit QFERStateInjected(
            rwaToken,
            qferRootHash,
            integrityIndexBps,
            computedHaircut,
            computedState,
            currentNonce
        );
    }

    /**
     * @notice Deterministic Basel III / MiCA risk engine computing dynamic collateral haircuts.
     */
    function _evaluateRiskParameters(
        uint16 integrityIndexBps
    ) internal view returns (AssetLifecycleState state, uint16 haircutBps) {
        if (integrityIndexBps >= 9500) {
            return (AssetLifecycleState.ACTIVE_VERIFIED, 150); // Prime condition: 1.50% base haircut
        } else if (integrityIndexBps >= criticalIntegrityThresholdBps) {
            uint16 degradation = 9500 - integrityIndexBps;
            return (AssetLifecycleState.ACTIVE_VERIFIED, 150 + degradation); // Proportional risk buffer
        } else if (integrityIndexBps >= 5000) {
            uint16 penalty = (criticalIntegrityThresholdBps - integrityIndexBps) * 2;
            return (AssetLifecycleState.DEGRADED_HAIRCUT, 2500 + penalty); // Heavy haircut enforced
        } else {
            return (AssetLifecycleState.FROZEN_REMEDIATION, MAX_BPS); // Critical hazard: 100% haircut & freeze
        }
    }

    /**
     * @notice External view hook for ERC-3643 Identity/Compliance modules and DeFi Repo pools.
     */
    function isAssetCompliantAndActive(address rwaToken) external view returns (bool) {
        AssetLifecycleState currentState = _assetStates[rwaToken].state;
        return (currentState == AssetLifecycleState.ACTIVE_VERIFIED || currentState == AssetLifecycleState.DEGRADED_HAIRCUT);
    }

    function getPhysicalState(address rwaToken) external view returns (PhysicalStateRecord memory) {
        return _assetStates[rwaToken];
    }

    function updateCriticalThreshold(uint16 newThresholdBps) external onlyRole(GOVERNANCE_ROLE) {
        require(newThresholdBps >= 5000 && newThresholdBps <= 9500, "Out of institutional bounds");
        criticalIntegrityThresholdBps = newThresholdBps;
    }
}
