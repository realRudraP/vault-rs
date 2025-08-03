# vault-rs

`vault-rs` is a command-line tool for managing secure file vaults. It allows you to create encrypted vaults to store your files securely.

## Building and Running

To build the project, run:

```bash
cargo build --release
```

To run the application:

```bash
./target/release/vault <COMMAND>
```

## Usage

### Create a new vault

To create a new vault, use the `new` command.

```bash
./target/release/vault new --name <VAULT_NAME>
```

You can also specify a path for the vault:

```bash
./target/release/vault new --name <VAULT_NAME> --path local://<PATH_TO_VAULT>
```

You will be prompted to enter a password for the new vault.

### List vaults

To see a list of all your vaults, use the `list` command.

```bash
./target/release/vault list
```
