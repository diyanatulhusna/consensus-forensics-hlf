# consensus-forensics-hlf

Code, benchmark configurations, scripts, figures, and experimental results for evaluating Raft and SmartBFT in Hyperledger Fabric under forensic-specific ordered workloads.

## Overview

This repository accompanies our study on consensus performance in Hyperledger Fabric for blockchain-based forensic evidence management in industrial Internet of Things (IIoT) environments. The evaluation focuses on two ordered transaction paths:

- `submitEvidence`
- `retrieveEvidenceAndLog`

The repository provides the forensic chaincode, benchmark workloads, Hyperledger Caliper configurations, experiment execution scripts, processed experimental results, and figure assets used in the paper.

## Research Scope

The study comparatively evaluates **Raft** and **SmartBFT** in **Hyperledger Fabric v3.x** under forensic-specific ordered workloads. The experiments cover:

- block size and offered transaction load
- inter-orderer delay / RTT
- orderer-cluster scaling
- fault placement
- fault count

The reported metrics include:

- latency
- throughput
- transaction outcome
- CPU utilization
- network traffic
- CPU per delivered throughput
- traffic per committed transaction

Although this study focuses on an IIoT forensic use case in Hyperledger Fabric, the proposed evaluation methodology can be adapted to other application domains and to blockchain or distributed-ledger platforms that employ comparable ordered-transaction architectures.

## Repository Structure

```text
benchmarks/   Hyperledger Caliper benchmark configuration files
chaincode/    Forensic smart contract and storage-related modules
Figs/         Figures used in the paper
networks/     Benchmark network connection/configuration files
results/      Processed experimental results and derived outputs
scripts/      Shell scripts for running evaluation scenarios
workload/     Benchmark workload entry points
shared/       Shared helper modules used across workloads

## Usage Notice

Copyright (c) [2026]. All rights reserved.

This repository is made publicly available for research transparency and reproducibility. No reuse, redistribution, or modification rights are granted without prior permission.

For permission requests, please contact: **husna.diyanatul.927@s.kyushu-u.ac.jp**
