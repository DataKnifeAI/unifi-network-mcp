# GitHub Actions Workflows

This project includes comprehensive GitHub Actions workflows modeled after the high-command projects, tailored for Go-based MCP servers.

## Workflows Overview

### 1. **tests.yml** - Continuous Integration Testing
- **Trigger**: Push to `main`/`develop`, Pull Requests
- **Matrix**: Tests on Ubuntu, macOS, Windows with Go 1.23, 1.24
- **Tasks**:
  - Run `go fmt` and `go vet` linters
  - Execute test suite with coverage reporting
  - Upload coverage to Codecov
  - Run Trivy security vulnerability scanner
  - Generate coverage HTML reports

### 2. **docker.yml** - Docker Build Verification
- **Trigger**: Push to `main`/`develop`, Pull Requests
- **Tasks**:
  - Build Docker image using Buildx
  - Cache layers via GitHub Actions cache
  - Test the built image
  - Support for multi-platform builds

### 3. **auto-approve.yml** - Automatic PR Approval
- **Trigger**: When `tests.yml` or `docker.yml` complete successfully
- **Requirements**:
  - All checks must pass
  - PR must exist
  - PR author must be a trusted collaborator (MEMBER, OWNER, COLLABORATOR)
- **Action**: Automatically approves PR with comment

### 4. **auto-assign.yml** - Automatic PR Assignment
- **Trigger**: When a Pull Request is opened
- **Action**: Automatically assigns the PR to its author

### 5. **release.yml** - Build and Release
- **Trigger**: When a version tag (v*) is pushed
- **Matrix**: Builds for:
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)
  - Windows (amd64)
- **Outputs**:
  - Compressed binaries (.tar.gz for Unix, .zip for Windows)
  - GitHub Release with all artifacts and auto-generated notes

## Usage

### Running Tests Locally
```bash
make test
```

### Building Docker Image Locally
```bash
docker build -t unifi-mcp:latest .
```

### Creating a Release
```bash
# Tag a release
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0

# GitHub Actions will automatically:
# 1. Build binaries for all platforms
# 2. Create a GitHub Release
# 3. Attach compiled binaries as assets
```

## Security Considerations

- **Trusted Approvals**: Only PRs from collaborators are auto-approved
- **Vulnerability Scanning**: Trivy scans the codebase for security issues
- **Coverage Reports**: Code coverage is tracked via Codecov
- **Docker Security**: Image is built and tested before deployment

## Customization

To modify workflows:
1. Edit files in `.github/workflows/`
2. Commit and push changes
3. Workflows are active immediately

## Integration with High-Command Projects

These workflows follow the same patterns as the high-command projects:
- Consistent naming and structure
- Multi-OS testing strategy
- Security-first approach with automated scanning
- Auto-approval for trusted contributors
- Release automation with cross-platform builds
