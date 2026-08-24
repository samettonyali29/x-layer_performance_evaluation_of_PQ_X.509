# Cross-Layer Performance Evaluation of Post-Quantum X.509 Authentication over Wi-Fi

Measurement data and simulation source accompanying the preprint:

> Samet Tonyalı, *A Cross-Layer Performance Evaluation of Post-Quantum X.509 Authentication over Wi-Fi* (2026).

This dataset evaluates certificate-based mutual authentication over a simulated IEEE 802.11n home Wi-Fi network. The experiment couples an ns-3 network model with native OpenSSL 3.5.7 signing, signature verification, and X.509 certificate-chain validation. Authentication-message sizes are derived from the actual DER-encoded certificates and generated signatures.

The study covers **18 classical** and **15 post-quantum** signature configurations in both end-entity and certification-authority (CA) signing roles. It includes homogeneous cross-products and two predefined heterogeneous assignments.

## Dataset integrity note

The supplied folder contains all **551 expected CSV files**, but this particular snapshot contains **407,867 data rows**, not the **439,830 completed exchanges** reported in the manuscript.

| Scenario | CSV files | Scheduled in manuscript | Completed in manuscript | Rows in this folder |
|---|---:|---:|---:|---:|
| 1 - homogeneous classical | 324 | 259,200 | 259,200 | 259,200 |
| 2 - homogeneous post-quantum | 225 | 180,000 | 179,030 | 147,271 |
| 3 - heterogeneous classical | 1 | 800 | 800 | 800 |
| 4 - heterogeneous post-quantum | 1 | 800 | 800 | 596 |
| **Total** | **551** | **440,800** | **439,830** | **407,867** |

Within Scenario 2, 110 CSVs contain all 800 rows, 107 are partially populated, and 8 contain only the header. Scenario 4 is also partial. Therefore, this folder should not be described as the complete version-of-record dataset without replacing or regenerating the affected files. The manuscript's 970 right-censored Scenario-2 exchanges alone do not explain the additional missing rows in this snapshot.

## What is measured

Each CSV row represents one **completed** four-message authentication exchange. Measurements span application, cryptographic, MAC, PHY, and topology layers.

| Layer | Measurements |
|---|---|
| Application | exchange delay, authentication-payload goodput |
| Cryptographic/X.509 | AP-side and STA-side signature/certificate-processing time; certificate-message sizes |
| MAC/PHY | PHY-observed throughput, mean PHY transmission duration, MAC failure/retry indicator, AP-side PHY-drop indicator |
| Topology | AP-STA propagation delay at exchange completion |

The modeled exchange is:

1. STA to AP: `ClientHello` (300 B).
2. AP to STA: `ServerHello` (700 B).
3. AP to STA: `ServerCertMsg` containing the AP certificate, representative CA certificate, 200 B of modeled overhead, and an AP handshake signature. The STA verifies the signature and validates the certificate chain.
4. STA to AP: `ClientCertMsg` containing the STA certificate, representative CA certificate, 200 B of modeled overhead, and a STA handshake signature. The AP verifies the signature and validates the certificate chain.

No key-exchange algorithm is executed. This is a controlled certificate-authentication abstraction, not a byte-for-byte implementation of TLS 1.3 or EAP-TLS.

## Evaluated configurations

| Class | Families/configurations | Homogeneous cross-product |
|---|---|---:|
| Classical | RSA-2048-PSS with SHA-224/SHA-256/SHA-384/SHA-512 and SHA3-224/SHA3-256/SHA3-384/SHA3-512; ECDSA P-256 with the same digest set; Ed25519; Ed448 | 18 x 18 = 324 runs |
| Post-quantum | ML-DSA-44/65/87; all 12 standardized SLH-DSA SHA2/SHAKE, category 1/3/5, `s`/`f` parameter sets | 15 x 15 = 225 runs |

The classical set is broader than the signature schemes negotiable in TLS 1.3. SHA-224 and SHA-3 combinations are included for controlled OpenSSL/X.509 comparisons.

## Repository structure

```text
.
|-- tls-wifi-sim.cc       # ns-3/OpenSSL simulation source
`-- results/
    |-- s1_*.csv          # homogeneous classical results (324 files)
    |-- s2_*.csv          # homogeneous post-quantum results (225 files)
    |-- s3_heterog_classic.csv
    `-- s4_heterog_pq.csv
```

The source file is at the repository root, not inside `results/`.

## Result-file naming

Homogeneous files use:

```text
s<scenario>_<end-entity-configuration>_signed-by_<CA-configuration>.csv
```

Examples:

```text
s1_ECDSA-SHA256_signed-by_RSA-SHA256.csv
s2_ML-DSA-44_signed-by_SLH-DSA-SHA2-192s.csv
```

`s3_heterog_classic.csv` and `s4_heterog_pq.csv` each contain one fixed assignment of eight configurations to the eight STAs. They are illustrative mixed deployments, not samples over multiple randomized assignments.

## CSV data dictionary

All result files use the same 17-column schema.

| Column | Unit | Definition |
|---|---:|---|
| `scenario` | - | Scenario number: 1 through 4. |
| `node_id` | - | ns-3 station node ID. IDs 1-4 are fixed STAs; 5-8 are mobile STAs. Node 0 is the AP. |
| `handshake_index` | - | Zero-based exchange index for the station. |
| `sta_cert_algo` | - | Label supplied for the station certificate configuration. In these files it commonly encodes `<end-entity>_signed-by_<CA>`. |
| `ap_cert_algo` | - | Label supplied for the AP certificate configuration. |
| `handshake_delay_ms` | ms | Time from `ClientHello` transmission to completion of `ClientCertMsg`. |
| `goodput_kbps` | kbit/s | Sum of the four modeled application payloads, divided by exchange duration. This is authentication-payload delivery rate, not link capacity. |
| `throughput_kbps` | kbit/s | Bytes observed at `PhyTxEnd`, divided by exchange duration. |
| `phy_frame_drop_rate` | fraction | `min(1, AP PhyRxDrop events / selected STA PhyTxEnd events)` during the exchange. This is a comparative indicator, not a strict per-STA loss probability. |
| `mac_retries` | events | Count of `MacTxDataFailed` trace events during the exchange. |
| `mac_retry_rate` | events/frame | `MacTxDataFailed` events divided by selected STA `PhyTxEnd` events. Treat as an indicator. |
| `tx_delay_us` | us | Mean interval from `PhyTxBegin` to `PhyTxEnd` for matching packet IDs; excludes contention/backoff before `PhyTxBegin`. |
| `prop_delay_ns` | ns | Constant-speed propagation delay calculated from AP-STA distance at exchange completion. |
| `cert_verify_ap_us` | us | AP-side time for STA handshake-signature verification and STA certificate-chain validation. |
| `cert_verify_sta_us` | us | STA-side time for AP handshake-signature verification and AP certificate-chain validation. |
| `server_cert_msg_bytes` | B | `AP certificate DER + CA certificate DER + 200 B + AP signature`. |
| `client_cert_msg_bytes` | B | `STA certificate DER + CA certificate DER + 200 B + STA signature`. |

## Experimental setup

| Category | Configuration |
|---|---|
| Host | Intel Core i5-3470 at 3.20 GHz, 4 physical cores, 15.8 GB DDR3 |
| OS | Ubuntu 26.04 LTS, Linux 7.0.0-28-generic, x86-64 |
| Compiler | GCC/G++ 15.2.0, C++23 |
| Simulator | ns-3.48, debug build |
| Cryptography | OpenSSL 3.5.7 default provider, built with `-O3`; no liboqs/OQS provider |
| Topology | One central AP; four fixed corner STAs; four mobile STAs in a 14 m x 10 m room |
| Wi-Fi | IEEE 802.11n, 2.4 GHz, 20 MHz, one spatial stream, `MinstrelHtWifiManager` |
| Mobility | `RandomWalk2dMobilityModel`, 0.7 m/s, reflective room boundary |
| Propagation | Yans channel; log-distance loss; constant-speed propagation delay |
| Randomization | `RngSeed=1`, `RngRun=1` for every run |
| Workload | 100 exchanges per STA; 8 STAs; 800 scheduled exchanges per run |
| Safety limit | 300 s per simulation run |

## Reproducing a run

### Prerequisites

- Linux environment matching, or carefully adapted from, the setup above.
- ns-3.48.
- OpenSSL 3.5.7 with native ML-DSA and SLH-DSA support.
- PEM certificates and matching private keys for the STA, AP, and CA roles.

Copy `tls-wifi-sim.cc` into the ns-3 `scratch/` directory and ensure the scratch target includes the OpenSSL headers and links to `libcrypto`. The supplied folder does **not** include the certificate/key-generation scripts, certificate artifacts, or ns-3/OpenSSL build glue, so exact end-to-end reproduction requires those external inputs.

The program accepts either one certificate/key/label value, which is replicated across all eight STAs, or eight colon-separated values for a heterogeneous assignment.

Example homogeneous invocation:

```bash
./ns3 run "scratch/tls-wifi-sim \
  --scenario=1 \
  --handshakesPerNode=100 \
  --simulationTime=300 \
  --csvFileName=results/s1_ECDSA-SHA256_signed-by_RSA-SHA256.csv \
  --staCertPaths=/path/to/sta-cert.pem \
  --staKeyPaths=/path/to/sta-key.pem \
  --apCertPaths=/path/to/ap-cert.pem \
  --apKeyPaths=/path/to/ap-key.pem \
  --caCertPaths=/path/to/ca-cert.pem \
  --staCertAlgos=ECDSA-SHA256_signed-by_RSA-SHA256 \
  --apCertAlgos=ECDSA-SHA256_signed-by_RSA-SHA256"
```

Additional options are `--roomWidth`, `--roomHeight`, and `--enablePcap`.

## Important caveats for reuse

- **Incomplete local snapshot.** Use the row-count audit above before analysis. Do not infer that every present filename contains a complete run.
- **Completion-conditioned results.** The program writes a row only when an exchange completes. The manuscript reports 970 Scenario-2 exchanges right-censored at 300 s; these are the slowest incomplete exchanges, so affected means and percentiles are biased downward.
- **Fixed wireless realization.** Every run uses one seed/run pair. Wireless metrics are descriptive for that realization and are not Monte Carlo confidence estimates.
- **PHY-drop indicator scope.** The AP-side drop numerator may include receptions associated with other STAs. It is not a strict per-STA packet-loss probability.
- **Single platform and implementation.** Absolute cryptographic timings and family rankings can change with processor, OpenSSL build, provider, compiler settings, and ns-3 build mode.
- **Simplified PKI and protocol.** One representative CA artifact is transmitted in each direction. The model omits key exchange, multilevel chains, record-layer details, trust-anchor provisioning choices, and the complete TLS/EAP state machines.
- **Modeled overhead.** The fixed 200-B additions support controlled relative comparisons; they are not exact TLS 1.3 or EAP-TLS record sizes.

## Manuscript-reported headline results

These values are quoted from the manuscript's analysis of its stated **439,830 completed records** and should not be assumed to be reproducible from the incomplete folder snapshot without restoring the missing rows.

| Metric | Classical | Post-quantum |
|---|---:|---:|
| Mean exchange delay | 16.13 ms | 1,655.53 ms |
| Mean STA certificate-processing time | 1.92 ms | 531.57 ms |
| Mean `ServerCertMsg` size | 1,638 B | 63,238 B |
| Mean `ClientCertMsg` size | 1,635 B | 63,235 B |

Within the post-quantum aggregate, the manuscript reports a mean exchange delay of **162.70 ms for ML-DSA** and **2,121.44 ms for SLH-DSA**. Fast-signing SLH-DSA variants completed sooner than their small-signature counterparts despite larger messages, indicating that cryptographic processing outweighed the communication benefit of smaller signatures in the evaluated environment.

## License

This project is licensed under the [MIT License](LICENSE).
