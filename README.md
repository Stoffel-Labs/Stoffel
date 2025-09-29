# Stoffel

A Stoffel MPC application

## Quick Start

```bash
# Run the application
stoffel run

# Development mode with hot reloading
stoffel dev

# Run tests
stoffel test

# Build optimized version
stoffel build --release
```

## Configuration

- **Protocol**: honeybadger (HoneyBadger MPC)
- **Parties**: 5 (minimum 5 for HoneyBadger)
- **Field**: bls12-381 (cryptographic field)
- **Threshold**: 1 (max corrupted parties)

## Language Ecosystem

This project was generated for the **basic** ecosystem.

## StoffelLang Implementation

This project uses pure StoffelLang for MPC computations:

- **Native MPC**: Built-in secret sharing and secure computation
- **Type Safety**: Strong typing with SecretInt and PublicInt
- **Performance**: Optimized for the StoffelVM execution environment

## StoffelLang Features

- Secret integer types with automatic MPC operations
- Built-in functions for secure computation (add, multiply, reveal)
- Support for complex data structures (vectors, structs)
- Privacy-preserving algorithms

## MPC Features

This application demonstrates:

- **Secure Computation**: Private inputs from multiple parties
- **Privacy Preservation**: Individual data never revealed
- **Result Reconstruction**: Only final results are disclosed
- **Healthcare Analytics**: Privacy-preserving medical statistics
- **Financial Risk**: Confidential portfolio risk assessment

## Learn More

- [Stoffel Documentation](https://docs.stoffel.dev)
- [MPC Introduction](https://docs.stoffel.dev/mpc-intro)
- [HoneyBadger Protocol](https://docs.stoffel.dev/honeybadger)
- [StoffelLang Guide](https://docs.stoffel.dev/language)
- [Python SDK](https://docs.stoffel.dev/python-sdk)
