# ptvs-rwa-oracle
PTVS v2.0 On-Chain Oracle. Bridges Google Cloud Confidential Space (AMD SEV-SNP) with ERC-3643 RWA tokens for dynamic regulatory capital adjustment.
# PTVS v2.0: On-Chain Oracle & Physical-State Risk Engine

**Prop Trust Verified Standard v2.0 (PTVS v2.0)** is the definitive technical specification for bridging the "Physical Oracle Gap" in Real-World Asset (RWA) tokenization. 

This repository contains the core smart contract (`PTVSClaimInjectorV2.sol`) that enables hardware-attested forensic evidence injection, zero-knowledge solvency verification, and dynamic regulatory capital adjustments.

## 🏛️ Institutional Backing
- **Governing Body:** [PropTrust Association](https://proptrust-association.ch) (Zug, Switzerland)
- **Lead Architect:** Aurelio Tamarit Blay (ORCID: [0009-0007-5824-3602](https://orcid.org/0009-0007-5824-3602))
- **Academic Registration:** CERN Zenodo DOI: [10.5281/zenodo.24322146](https://doi.org/10.5281/zenodo.24322146)
- **Regulatory Alignment:** MiCA (EU 2023/1114), Basel III (SCO60), eIDAS 2.0, ERC-3643.

## 📐 Core Architecture (RFC-004 to RFC-007)
1. **RFC-004:** Hardware-Attested Edge Capture (Secure Enclave + Galileo OSNMA + eIDAS 2.0 QES).
2. **RFC-005:** Privacy-Preserving Planetary Telemetry (InSAR via Google Cloud Confidential Space / AMD SEV-SNP).
3. **RFC-006:** Zero-Knowledge Physical Solvency Vaults (ZK-SNARKs for regulatory compliance without data leakage).
4. **RFC-007:** Dynamic Physical-State Risk & Parametric Escrow (Automated collateral haircuts based on the $I_{fis}$ index).

## 🛠️ Technical Specifications
- **Solidity Version:** `^0.8.24`
- **License:** [Business Source License 1.1 (BUSL-1.1)](./LICENSE)
- **Token Standard Compatibility:** ERC-3643 (T-REX / ONCHAINID)

## 📊 Regulatory Capital Simulator
See the economic impact of PTVS v2.0 on institutional balance sheets:  
🔗 [PTVS v2.0 Basel III & MiCA Regulatory Capital Simulator](https://forensics-oracle.org/verify/ptvs-v2-0-basel-iii-sco60-mica-regulatory-capital-simulator/)

## 🚀 Installation & Compilation

```bash
# Clone the repository
git clone https://github.com/aurema-group/ptvs-rwa-oracle.git
cd ptvs-rwa-oracle

# Install dependencies
npm install

# Compile the contracts
npx hardhat compile


---

#### **ARCHIVO 2: `LICENSE`** (El escudo legal)
*Protege tu propiedad intelectual mientras permite la auditoría pública.*

```text
Business Source License 1.1

License text for the Prop Trust Verified Standard (PTVS) Smart Contracts.

Parameters
Licensor:             PropTrust Association (Zug, Switzerland) / Aurema Group LLC
Licensed Work:        PTVSClaimInjectorV2.sol and associated PTVS v2.0 smart contracts
                      The Licensed Work is (c) 2026 Aurelio Tamarit Blay
Additional Use Grant: You may make use of the Licensed Work for non-commercial 
                      auditing, academic research, and testing purposes. Any 
                      commercial deployment or integration requires an explicit 
                      commercial license from the Licensor.
Change Date:          2028-11-24
Change License:       GNU General Public License v3.0 or later

For commercial licensing inquiries, contact: governance@forensics-oracle.org

Full License Text: https://mariadb.com/bsl11/
📚 Documentation & Resources
Full Technical Whitepaper: proptrust-association.ch/standard-ptvs-v2-0
Book: PTVS v2.0: The Autonomous Physical Oracle (Available on Google Play Books & Amazon)
Contact: governance@forensics-oracle.org
