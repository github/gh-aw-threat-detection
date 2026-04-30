# Contributing to gh-aw-threat-detection

Thank you for your interest in contributing to gh-aw-threat-detection! We welcome contributions from the community and are excited to work with you.

## Prerequisites

- Go 1.23+
- Docker (for container builds)

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch (`git checkout -b my-feature`)
4. Make your changes
5. Run tests and linting (see below)
6. Commit your changes (`git commit -am 'Add my feature'`)
7. Push to the branch (`git push origin my-feature`)
8. Open a Pull Request

## Development

### Build

```bash
make build
```

### Test

```bash
make test
```

### Lint

```bash
make lint
```

### Docker

```bash
make docker-build
```

## Reporting Issues and Feature Requests

Please use GitHub Issues to report bugs or request features. Before opening a new issue, search existing issues to avoid duplicates.

When reporting a bug, include:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Go version, etc.)

## Pull Request Process

1. Ensure your code passes all tests and lint checks
2. Update documentation if your change affects public APIs or usage
3. Add tests for new functionality
4. Keep pull requests focused — one feature or fix per PR

## Style Guide

- Follow standard Go conventions (`gofmt`, `go vet`)
- Write clear commit messages
- Add comments for exported functions and packages

## Code of Conduct

This project has adopted the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).
