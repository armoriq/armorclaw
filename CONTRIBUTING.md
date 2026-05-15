# Contributing to ArmorIQ OpenClaw Plugin

Thank you for your interest in contributing!

## Development Setup

1. Fork and clone the repository
2. Install dependencies: `npm install`
3. Build: `npm run build`
4. Test: `npm test`

## Testing Locally

```bash
# Build the plugin
npm run build

# Install in OpenClaw
openclaw plugins install .

# Test with OpenClaw
openclaw gateway run
```

## Pull Request Process

1. Create a feature branch
2. Make your changes
3. Add tests if applicable
4. Ensure `npm run build` and `npm test` pass
5. Submit a pull request

## Code Style

- Follow existing TypeScript conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small

## Reporting Issues

Please use GitHub Issues and include:

- OpenClaw version
- Plugin version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

## Questions?

Join our Discord or email support@armoriq.ai
