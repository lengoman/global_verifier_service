# Global Verifier Service

A Rust-based service for signing and verifying messages using RSA cryptography.

## Project Structure

The project is organized into the following modules:

- `common`: Shared functionality used across the application
   - `signer`: Common signing functionality
   - `verify`: Common verification functionality
   - `types`: Common data structures used across the application
- `client`: This contains the possible client implementations
  - `holder`: This is the client that signs messages and sends them to a verifier
- `services`: Individual service implementations
   - `verifier`: HTTP server for verifying signatures for local testing and development
   - `lambda`: AWS Lambda function for verifying signatures
   - `holder`: Client for signing messages and sending them to a verifier
- `utils`: For future utilities to generate RSA key pairs
  - `keygen`: Utility for generating RSA key pairs

## Building and Running

### Note: Use the private_key.pem file sent to you in the email

### Run the Holder Client for remote Lambda Testing

```bash
cargo run --bin holder <Lambda URL sent by email>
```      

### Run the Verifier Service  for local testing
For local test you need to run first:
```bash
cargo run --bin verifier
```

The service will listen on `http://localhost:3040/verify`.

### Run the Holder Service for Local Testing

Run the holder service to sign a message and send it to the verifier:

```bash
cargo run --bin holder
```

### If you want to regenerate a new key pair, run the following command:
Note that this is going to replace the existing private_key, therefore it would not allow you to connect to the remote lambda.
```bash

### Generate Keys

First, generate a new RSA key pair:

```bash
cargo run --bin keygen
```

This will create `private_key.pem` and `public_key.pem` files.

### Deploy the Lambda Function

Build and deploy the Lambda function:

```bash
cargo lambda build --release --bin global_verifier_lambda --target aarch64-unknown-linux-gnu
cargo lambda deploy global_verifier_lambda --iam-role <IAM Role ARN>

```

## Testing Locally

You can test the Lambda function locally:

```bash
cargo lambda watch
```

## Environment Variables

- `PRIVATE_KEY_PEM`: The private key in PEM format (optional, defaults to reading from file)
- `PUBLIC_KEY_PEM`: The public key in PEM format (optional, defaults to reading from file)
