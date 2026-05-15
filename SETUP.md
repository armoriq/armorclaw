# Setup Guide for ArmorIQ OpenClaw Plugin

## For Plugin Developers

### Initial Setup

```bash
cd /Users/rfievet3/projects/ArmorIQ/armoriq-openclaw-plugin

# Initialize git
git init
git add .
git commit -m "Initial commit: ArmorIQ OpenClaw plugin"

# Create GitHub repo (via GitHub CLI or web)
gh repo create armoriq/armoriq-openclaw-plugin --public --source=. --remote=origin
git push -u origin main

# Install dependencies
npm install
```

### Development Workflow

```bash
# Build the plugin
npm run build

# Watch mode for development
npm run dev

# Run tests
npm test

# Test locally with OpenClaw
openclaw plugins install .
openclaw gateway run
```

### Testing Against Vanilla OpenClaw

**Option 1: Global OpenClaw Install**

```bash
# Install OpenClaw globally
npm install -g openclaw

# Install your plugin locally
cd /Users/rfievet3/projects/ArmorIQ/armoriq-openclaw-plugin
npm run build
openclaw plugins install .

# Test
openclaw plugins list
openclaw gateway run
```

**Option 2: Local OpenClaw Clone**

```bash
# Clone vanilla OpenClaw (separate from aiq-openclaw fork)
cd /Users/rfievet3/projects
git clone https://github.com/openclaw/openclaw.git openclaw-vanilla
cd openclaw-vanilla
pnpm install
pnpm build

# Install your plugin
pnpm openclaw plugins install /Users/rfievet3/projects/ArmorIQ/armoriq-openclaw-plugin

# Test
pnpm openclaw gateway run
```

### Publishing to npm

```bash
# Login to npm (use ArmorIQ npm account)
npm login

# Bump version
npm version patch  # or minor, or major

# Publish (GitHub Actions will do this on release)
npm publish --access public
```

### Creating a Release

```bash
# Tag and push
git tag v1.0.0
git push origin v1.0.0

# Or use GitHub CLI
gh release create v1.0.0 --title "v1.0.0" --notes "Initial release"
```

## For End Users

### Installation

```bash
# Install OpenClaw
npm install -g openclaw

# Install ArmorIQ plugin
openclaw plugins install @openclaw/armoriq
```

### Configuration

```bash
# Configure via CLI
openclaw config set plugins.entries.armoriq.enabled true
openclaw config set plugins.entries.armoriq.apiKey "ak_live_xxx"
openclaw config set plugins.entries.armoriq.userId "user-123"
openclaw config set plugins.entries.armoriq.agentId "agent-456"

# Or edit ~/.openclaw/openclaw.json directly
```

### Verification

```bash
# Check plugin is installed
openclaw plugins list

# Check plugin info
openclaw plugins info armoriq

# Start gateway
openclaw gateway run
```

## Project Structure

```
armoriq-openclaw-plugin/
├── .github/
│   └── workflows/          # CI/CD pipelines
├── src/                    # Source files
│   ├── crypto-policy.service.ts
│   ├── iap-verfication.service.ts
│   └── policy.ts
├── test/                   # Test files
├── dist/                   # Build output (gitignored)
├── index.ts                # Main plugin entry
├── openclaw.plugin.json    # Plugin manifest
├── package.json            # npm package config
├── tsconfig.json           # TypeScript config
├── README.md               # User documentation
├── CONTRIBUTING.md         # Contributor guide
├── LICENSE                 # MIT license
└── SETUP.md                # This file
```

## Relationship to Other Projects

- **aiq-openclaw/** - Fork with integrated demo (keep for reference)
- **armoriq-openclaw-plugin/** - Standalone plugin (publish this)
- **armoriq-sdk-customer-ts/** - SDK used by plugin
- **conmap-auto/** - ArmorIQ backend API

## Next Steps

1. ✅ Create GitHub repository
2. ✅ Set up npm publishing
3. Test with vanilla OpenClaw
4. Publish v1.0.0 to npm
5. Announce on OpenClaw Discord
6. Update ArmorIQ documentation
