# Vault-rs: A Secure Vault Engine for Cross-Platform Apps

Vault-rs is a secure vault engine written in Rust. My goal is to create a single, reliable core library that can power multiple frontends:

1.  A fast, modern **Command-Line Interface (CLI)** for scripting and terminal-based access.
2.  A cross-platform **Desktop GUI** built with [Tauri](https://tauri.app/).
3.  A **Mountable Virtual Filesystem** using [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace), allowing vaults to be used like any other drive on the system.

This project began as a personal mission to improve upon and robustly rebuild a [cryptography project I created for a university course](https://github.com/realRudraP/Vault). This new version is a complete rewrite, architected from the ground up to support the ambitious goals listed above.

## My Goals for This Project

My focus is on learning and demonstrating key software engineering principles through this multi-faceted application:

*   **Secure by Design:** To correctly implement modern, robust cryptographic protocols (Argon2 for key derivation, AES-256-GCM for authenticated encryption).
*   **Architectural Foresight:** To build a reusable core library capable of supporting diverse frontends (CLI, GUI, virtual filesystem) from a single, secure codebase. This is the project's central challenge and goal.
*   **Rust Mastery:** To gain a deeper, practical understanding of Rust's powerful features to build a reliable and performant application.
*   **Professional Tooling:** To practice and implement a full suite of professional development tools, including comprehensive testing and CI/CD pipelines.

## Architectural Overview

The project's architecture is intentionally designed to support the long-term vision. It is built on a clean separation between the core engine and its consumers.

### `vault-core` (The Engine)

This is a self-contained library crate that contains all the critical logic and knows nothing about how it will be presented to the user.

*   **`UnlockedVault`:** An expert on a *single* vault. It handles all low-level cryptographic operations, manages the internal file/directory structure, and interacts with a generic `StorageBackend` trait.
*   **`VaultManager`:** An application-level operator that manages the entire ecosystem of vaults, their locations, and their high-level state (e.g., which vaults are unlocked).

### The Consumers (The Frontends)

The `vault-core` engine is designed to be used by different frontends.

*   **CLI (`bin.rs`):** The current command-line interface is the **first consumer** of the engine. It provides a direct, terminal-based way to interact with the vault's core logic.
*   **Tauri App (Future):** The planned desktop app will be the second consumer. It will use the exact same `vault-core` library for all its vault operations, ensuring consistency and security.
*   **FUSE Driver (Future):** The virtual filesystem will be the third consumer, translating filesystem calls (e.g., `read`, `write`) into commands for the `vault-core` engine.

This clean split is what makes the project's vision possible, preventing code duplication and ensuring that all frontends are powered by the same secure, tested core.

## Project Roadmap

My development plan is broken down into three main phases:

#### Phase 1: Core Engine & CLI (Current Focus)
This phase is about building a rock-solid foundation.
- [ ] Solidify the core cryptographic and vault management logic.
- [ ] Build out a feature-complete and robust CLI.
- [ ] Establish a comprehensive suite of unit and integration tests.
- [ ] Set up a CI/CD pipeline for automated testing and quality checks.

#### Phase 2: Desktop GUI
Once the core engine is stable, I will begin work on the desktop experience.
- [ ] Develop a cross-platform GUI using Tauri.
- [ ] Design a user-friendly interface for managing vaults, files, and directories.
- [ ] Ensure seamless integration with the `vault-core` library.

#### Phase 3: Virtual Filesystem
This is the most ambitious phase, aiming for deep OS integration.
- [ ] Implement a FUSE driver to mount unlocked vaults as virtual drives.
- [ ] Handle filesystem operations by translating them to vault-core functions.
- [ ] Focus on performance and stability.

## Contributing & Feedback

Even though this is my solo project, I believe that collaboration and external feedback are the best ways to learn and improve. Given the project's ambitious roadmap, I would be incredibly grateful for any advice or support.

**I am actively seeking feedback and contributions in all areas, especially:**

*   **Code Reviews:** Are there more idiomatic or efficient ways to implement certain features in Rust?
*   **Architectural Suggestions:** Do you see potential improvements in the current design, especially regarding the long-term goals?
*   **Security Analysis:** Have you spotted any potential security vulnerabilities? (Please report these responsibly by opening an issue).
*   **Experience with Tauri or FUSE:** If you have experience building Tauri apps or working with FUSE in Rust, I would be especially grateful for your insights.

### How You Can Help

1.  **Find an issue** or propose a new feature/improvement by creating a new issue.
2.  **Fork the repository** and create a new branch for your feature or bugfix.
3.  **Open a Pull Request** against the `main` branch, clearly describing the changes you've made and why.

I appreciate any and all contributions that help make this a better project.