# Contributing to Stoffel

Thank you for your interest in contributing to Stoffel! We welcome meaningful contributions that help advance secure multiparty computation technology.

## 🚨 Anti-Spam Policy

**We do not accept:**
- AI-generated pull requests without substantial human review and understanding
- Trivial typo fixes or minor formatting changes
- Mass automated contributions across repositories
- Pull requests that show no understanding of the codebase or MPC concepts

**All contributors must:**
- Demonstrate genuine understanding of the changes they propose
- Include detailed explanations of their reasoning and approach
- Show familiarity with MPC concepts and StoffelLang when relevant

## 📋 Before You Contribute

### Read and Understand
1. **Read the README thoroughly** - Understand what Stoffel does and how it works
2. **Explore the codebase** - Familiarize yourself with the project structure
3. **Test the CLI** - Try the commands and understand the user experience
4. **Review existing issues** - Check if your contribution addresses known problems

### Technical Prerequisites
- Experience with Rust programming language
- Familiarity with CLI design principles and command-line tools
- Understanding of build systems and project scaffolding
- Basic knowledge of template systems and code generation

### Repository Scope
This CLI repository focuses specifically on:
- **Project scaffolding** - Templates and project initialization
- **Development tools** - Build, compile, and development commands
- **Developer experience** - Help systems, error messages, and workflow optimization
- **Integration** - Connecting with StoffelLang compiler and runtime components

**Out of scope for this repository:**
- MPC protocol implementations (separate repositories)
- StoffelLang compiler development (Stoffel-Lang repository)
- VM runtime and execution engine (StoffelVM repository)
- SDK implementations (language-specific SDK repositories)

## 🎯 What We're Looking For

### High-Value Contributions
- **CLI performance optimizations** - Improvements to command execution speed, file processing, or build times
- **Developer experience enhancements** - Better error messages, improved help system, workflow optimizations
- **Template system improvements** - New language ecosystem templates, better project scaffolding
- **Documentation improvements** - Comprehensive CLI guides, tutorials, or API documentation
- **Test coverage expansion** - Integration tests for CLI commands, template generation tests, compilation tests
- **Build system improvements** - Cross-platform support, dependency management, packaging

### Medium-Value Contributions
- **New language templates** - Support for additional programming language ecosystems
- **CLI usability improvements** - Enhanced command interfaces, better flag documentation
- **Integration features** - Support for new deployment targets, IDE plugins, development environment integrations
- **Configuration management** - Improved project configuration, template customization

### Not Accepted
- Simple typo fixes or cosmetic changes
- Automated code style adjustments without functional improvements
- Adding comments without improving code clarity
- Renaming variables for aesthetic reasons
- Trivial refactoring without performance or maintainability benefits
- **Underlying MPC protocol implementations** - These belong in separate repositories, not the CLI
- **StoffelLang compiler changes** - Language development happens in the Stoffel-Lang repository

## 🚀 How to Contribute

### 1. Start with an Issue
**Required for all contributions:**
- Open an issue describing your proposed contribution
- Explain the problem you're solving and your proposed approach
- Wait for maintainer feedback before starting implementation
- Reference the issue number in your pull request

### 2. Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd Stoffel

# Build dependencies
cargo build

# Build Stoffel-Lang compiler (required for testing)
cd ../Stoffel-Lang
cargo build
cd ../Stoffel

# Run tests
cargo test

# Test CLI functionality
cargo run -- --help
cargo run -- init test-project
cargo run -- compile test-project/src/main.stfl
```

### 3. Development Guidelines

#### Code Quality Standards
- **Rust best practices** - Follow idiomatic Rust patterns and conventions
- **Error handling** - Use proper Result types and meaningful error messages
- **Documentation** - Include inline documentation for public APIs
- **Testing** - Add unit tests for new functionality
- **Security** - Consider security implications of all changes

#### Commit Guidelines
- **Meaningful messages** - Describe what and why, not just what changed
- **Atomic commits** - One logical change per commit
- **No merge commits** - Rebase feature branches before submitting
- **Sign commits** - Use `git commit -S` for verified commits (recommended)

#### CLI-Specific Considerations
- **Command correctness** - Ensure CLI commands work as documented and handle edge cases
- **Cross-platform compatibility** - Verify commands work on Linux, macOS, and Windows
- **Template generation** - Ensure generated projects compile and run successfully
- **Error handling** - Provide clear, actionable error messages for common failure cases
- **Integration testing** - Test CLI commands with real StoffelLang files and project structures

### 4. Pull Request Process

#### Before Submitting
- [ ] All tests pass locally
- [ ] Code follows project style conventions
- [ ] Documentation is updated for user-facing changes
- [ ] Commit messages are clear and descriptive
- [ ] Branch is rebased on latest main
- [ ] You've tested the changes with real StoffelLang programs

#### Pull Request Template
```markdown
## Summary
Brief description of changes and motivation.

## Related Issue
Fixes #<issue-number>

## Changes Made
- Detailed list of changes
- Why each change was necessary
- Any potential side effects

## Testing
- How you tested the changes
- Test cases added or modified
- Manual testing performed

## CLI Impact
- Effect on command performance and usability
- Cross-platform compatibility considerations
- Template generation and compilation testing results

## Reviewer Checklist
- [ ] Code review completed
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Security implications reviewed
- [ ] Performance impact assessed
```

## 🔐 Security Contributions

### Reporting Security Issues
- **Do not open public issues for security vulnerabilities**
- Contact maintainers privately via [security contact method]
- Provide detailed information about the vulnerability
- Allow reasonable time for fixes before public disclosure

### Security Review Process
- All cryptographic changes require additional review
- Protocol modifications must include formal security analysis
- Performance optimizations must not compromise security properties

## 🧪 Testing Guidelines

### Required Testing
- **Unit tests** for all new functions and methods
- **Integration tests** for CLI command functionality
- **Template tests** for project generation and compilation
- **Cross-platform tests** for command compatibility

### Testing Best Practices
- Test both success and failure cases
- Include edge cases and boundary conditions
- Test cross-platform compatibility when relevant
- Verify error messages are helpful and accurate

## 📚 Documentation Standards

### Code Documentation
- Public APIs must have complete rustdoc comments
- Include usage examples for complex functions
- Document safety requirements and invariants
- Explain CLI-specific behavior and assumptions

### User Documentation
- Update README for user-visible changes
- Include help text for new CLI flags or commands
- Provide examples for new features
- Update project templates if structure changes

## 🤝 Community Guidelines

### Communication Standards
- **Be respectful** - Treat all contributors with respect
- **Be constructive** - Provide helpful feedback and suggestions
- **Be patient** - Allow time for review and discussion
- **Be transparent** - Explain your reasoning and decision-making process

### Code of Conduct
- Follow standard open-source community guidelines
- No harassment, discrimination, or inappropriate behavior
- Maintain professional and inclusive communication
- Report concerning behavior to project maintainers

## 📝 License Agreement

By contributing to Stoffel, you agree that:
- Your contributions will be licensed under the Apache License, Version 2.0
- You have the right to submit your contributions
- You understand the implications of the open-source license

## 🎓 Learning Resources

### MPC and Cryptography
- [Multiparty Computation: Theory and Practice](https://example.com)
- [HoneyBadger MPC Protocol](https://example.com)
- [Secure Computation Fundamentals](https://example.com)

### Rust Development
- [The Rust Programming Language](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Cargo Guide](https://doc.rust-lang.org/cargo/)

## 💬 Getting Help

- **General questions** - Open a discussion in GitHub Discussions
- **Bug reports** - Open an issue with detailed reproduction steps
- **Feature requests** - Open an issue with clear motivation and use cases
- **Development help** - Reach out to maintainers or community members

---

**Remember**: Quality over quantity. We prefer fewer, well-thought-out contributions over many trivial changes. Take time to understand the project and make meaningful improvements that benefit the MPC development community.