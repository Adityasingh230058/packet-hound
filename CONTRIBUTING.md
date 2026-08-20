# Contributing to packet-hound

Thank you for contributing to **packet-hound**!

## 🛠️ Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/packet-hound.git
   cd packet-hound
   ```

2. **Create a virtual environment and install in editable mode:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Run the test suite:**
   ```bash
   pytest --cov=packet_hound --cov-report=term-missing tests/
   ```

## 📋 Pull Request Guidelines

- Ensure packet dissection or threat detection logic includes automated unit tests with binary `.pcap` fixtures under `tests/`.
- Adhere to PEP 8 and Python typing standards.
- Use descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) specification.
