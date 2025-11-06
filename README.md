# Guardian

A decentralized cross-chain bridge guardian node for the Zera-Solana blockchain bridge. This system monitors, validates, and facilitates asset transfers between the Zera blockchain and Solana networks through a multi-signature consensus mechanism.

> **⚠️ IMPORTANT NOTE**: This repository is provided as a **reference implementation and code example**. It is not intended to be built or deployed directly. The code demonstrates the architecture and design patterns used in the Zera-Solana bridge guardian system. Build artifacts, dependencies, and deployment configurations have been excluded.

## Overview

Guardian is a critical infrastructure component that operates as a distributed validator node in a multi-party bridge system. It listens to events on both Zera and Solana blockchains, validates cross-chain transactions, and coordinates with other guardian nodes to authorize asset transfers through a threshold signature scheme.

## Architecture

The system consists of two main components working in tandem:

### 1. **C++ Processor** (`cpp_processor/`)
The core processing engine that handles:
- Event processing and validation
- Guardian coordination and consensus
- Database management (RocksDB)
- gRPC services for inter-guardian communication
- Cryptographic operations (Ed25519 signatures, SHA2 hashing)
- Payload construction and verification

### 2. **Rust Subscriber** (`rust_subscriber/`)
A high-performance Solana blockchain subscriber that:
- Monitors Solana program logs in real-time via WebSocket
- Handles backfilling of historical transactions
- Manages subscription state persistence
- Provides FFI interface to C++ processor

## Key Features

### Cross-Chain Operations
- **Contract Creation**: Deploy new token contracts on Solana for Zera assets
- **Minting**: Issue wrapped tokens on either chain
- **Release**: Unwrap and release native tokens
- **Pause/Unpause**: Emergency bridge controls
- **Guardian Key Updates**: Dynamic guardian set management
- **Bridge Upgrades**: Upgrade bridge program on Solana

### Security
- Multi-signature consensus with configurable threshold (e.g., 2-of-3)
- Ed25519 cryptographic signatures
- SHA2 256 hashing for payload integrity
- Secure key management
- Finalized transaction confirmations

### High Availability
- Automatic reconnection with exponential backoff
- State persistence for crash recovery
- Thread pool for concurrent processing
- Event backfilling for historical data

## Components

### Event Handlers (`cpp_processor/src/events/`)
- `zera_events.cpp` - Processes Zera blockchain events
- `solana_events.cpp` - Processes Solana program logs
- `gov_events.cpp` - Handles governance events

### gRPC Services (`cpp_processor/src/grpc/`)
- `grpc_service.cpp` - Main API service
- `guardians_service.cpp` - Inter-guardian communication
- `txn_client.cpp` - Transaction submission client
- Guardian consensus protocol implementation

### Database (`cpp_processor/src/database/`)
- RocksDB-based persistence layer
- Stores guardian state, payloads, and signatures
- Configuration and metadata management

### Utilities (`cpp_processor/src/util/`)
- `signatures.cpp` - Ed25519 signature operations
- `base58.cpp` / `base64.cpp` - Encoding utilities
- `solana_subscriber.cpp` - Solana event parser
- `wallets.cpp` - Wallet management
- `threadpool.cpp` - Concurrent task execution

### Protocol Definitions (`cpp_processor/src/proto/`)
- `guardian.proto` - Guardian service and payload definitions
- `txn.proto` - Transaction structures
- `validator.proto` - Validator interfaces
- `zera_api.proto` - Zera API definitions

## Dependencies

### C++ Dependencies
- **CMake** >= 3.16
- **C++17** compiler (GCC/Clang)
- **gRPC** & **Protobuf** - RPC framework
- **RocksDB** - Embedded database
- **OpenSSL** - Cryptographic operations
- **libsodium** - Ed25519 signatures
- **CURL** - HTTP requests
- **nlohmann_json** - JSON parsing

### Rust Dependencies
- **Rust** 2021 edition
- **solana-client** 2.1 - Solana RPC client
- **solana-sdk** 2.1 - Solana primitives
- **crossbeam-channel** - Async message passing
- **serde_json** - JSON serialization

## Building

### 1. Build Rust Subscriber
```bash
cd rust_subscriber
cargo build --release
cd ..
```

### 2. Generate Protobuf Code
```bash
cd cpp_processor
mkdir -p generated
protoc --cpp_out=generated --grpc_out=generated --plugin=protoc-gen-grpc=$(which grpc_cpp_plugin) \
  src/proto/*.proto
cd ..
```

### 3. Build C++ Processor
```bash
cd cpp_processor
mkdir -p build
cd build
cmake ..
make -j$(nproc)
```

## Configuration

The guardian node is configured via environment variables:

### Required Variables
```bash
# Guardian Identity
PRIVATE_KEY=<base58_ed25519_private_key>
PUBLIC_KEY=<base58_ed25519_public_key>

# Network Configuration
HOST=<guardian_host_address>
PORT=<guardian_port>
INSTANCE=<guardian_instance_number>

# Smart Contract
SMART_CONTRACT_ID=<zera_smart_contract_id>
SOLANA_PROGRAM_ID=<solana_program_pubkey>

# Validator Connection
TRUSTED_VALIDATOR_HOST=<zera_validator_host>
TRUSTED_VALIDATOR_TXN_HOST=<validator_transaction_host>
```

### Optional Variables
```bash
# Solana RPC Endpoints
WS_URL=wss://api.mainnet-beta.solana.com/  # WebSocket URL
HTTP_URL=https://api.mainnet-beta.solana.com/  # HTTP RPC URL

# Database
DATABASE_RESET=false  # Set to 'true' to reset database on startup

# Backfill Configuration
BACKFILL_ON_START=false  # Enable historical transaction backfill
BACKFILL_ENABLED=false  # Enable backfill feature
BRIDGE_STATE_PATH=/app/state.json  # State persistence file

# Event Search
ZERA_SEARCH_TIME=<unix_timestamp>  # Search for events from this time
```

## Running

```bash
cd cpp_processor/build
export PRIVATE_KEY=your_private_key
export PUBLIC_KEY=your_public_key
export SOLANA_PROGRAM_ID=your_program_id
# ... set other required env vars ...
./cpp_processor
```

The guardian will:
1. Initialize database and configuration
2. Connect to trusted validator
3. Subscribe to Solana program logs
4. Start gRPC services on ports 50054 and 50055
5. Begin processing cross-chain events

## How It Works

### Event Flow

1. **Detection**: Rust subscriber detects a Solana program log or Zera event
2. **Parsing**: Event is parsed and validated by the C++ processor
3. **Payload Creation**: A standardized payload is constructed
4. **Signing**: Guardian signs the payload with its private key
5. **Consensus**: Guardian communicates with peers to gather signatures
6. **Threshold Check**: Once threshold signatures are collected (e.g., 2-of-3)
7. **Execution**: Transaction is submitted to the target chain

### Multi-Signature Consensus

Guardians operate in a distributed consensus model:
- Each guardian independently validates events
- Signs valid events with their private key
- Shares signatures with peer guardians via gRPC
- Collects signatures from peers
- Executes action once threshold is met (e.g., 2 out of 3 signatures)

### Database Schema

The system maintains several databases:
- **Payloads**: Stores transaction payloads by hash
- **Guardians**: Stores guardian authentication and configuration
- **Signatures**: Tracks collected signatures per payload
- **State**: Maintains system state and checkpoints

## API Services

### Guardian Service (Port 50055)
- `GetPayload` - Retrieve payload by ID
- `SearchPayload` - Search payloads by timestamp
- `AuthenticateGuardian` - Exchange signatures with peer guardians

### Main API Service (Port 50054)
- Activity subscription and event streaming
- Smart contract interaction
- Transaction status queries

## Security Considerations

1. **Private Key Protection**: Never expose private keys. Use environment variables or secure vaults.
2. **Network Security**: Guardians should run behind firewalls with restricted gRPC access.
3. **Multi-Signature**: The threshold signature scheme requires multiple guardians to collude for malicious activity.
4. **Finalized Confirmations**: Only processes finalized transactions to prevent reorganization attacks.

## Development

### Adding New Event Types

1. Define the event structure in the appropriate `.proto` file
2. Implement parsing logic in `solana_events.cpp` or `zera_events.cpp`
3. Add payload construction in `payload.cpp`
4. Update signature logic in `signatures.cpp`

### Testing

The system includes:
- Unit tests for cryptographic operations
- Integration tests for event processing
- End-to-end tests for cross-chain transfers

## Monitoring

The guardian logs important events to stdout:
- Subscription status
- Event processing
- Signature collection
- Transaction submission
- Error conditions

Monitor logs for:
- Subscription disconnections
- Failed signature attempts
- Consensus failures
- Database errors

## Troubleshooting

### Subscription Fails to Start
- Verify `SOLANA_PROGRAM_ID` is correct
- Check `WS_URL` connectivity
- Ensure Rust library is built and accessible

### Guardian Cannot Connect to Peers
- Verify network connectivity between guardians
- Check firewall rules for gRPC ports
- Validate guardian configuration in database

### Database Errors
- Check disk space
- Verify write permissions
- Use `DATABASE_RESET=true` to reset (WARNING: loses state)

