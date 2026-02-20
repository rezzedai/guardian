# Contributing to Guardian

We appreciate contributions to make guardian safer and more useful.

## Setup

1. **Clone the repo**

```bash
git clone https://github.com/rezzedai/guardian.git
cd guardian
```

2. **Install dependencies**

```bash
npm install
```

3. **Build**

```bash
npm run build
```

## Testing

Run the test suite:

```bash
npm test
```

Tests live in `test/` and use Node.js native test runner.

## Making Changes

1. **Create a branch**

```bash
git checkout -b feat/your-feature
```

2. **Make your changes**

- Add tests for new features
- Update README.md if adding CLI commands or policy options
- Follow existing code style (TypeScript, no runtime dependencies)

3. **Test your changes**

```bash
npm test
```

4. **Commit with clear messages**

```bash
git commit -m "feat: add X" # or fix: / docs: / test: / chore:
```

## Pull Requests

1. Push your branch:

```bash
git push origin feat/your-feature
```

2. Open a PR on GitHub

3. Describe what changed and why

4. Wait for CI to pass

We review PRs within a few days.

## Adding Blocklist Patterns

When adding new dangerous patterns to the default policy:

- Include clear reason strings
- Set appropriate severity (critical/high/medium/low)
- Add test cases in `test/patterns.test.js`
- Document in README.md "Built-in Patterns" section

## License

By contributing, you agree your contributions will be licensed under MIT.
