FROM python:3.11-slim

# Install build deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl build-essential pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# Compile Rust native core (optional - fallback to Python if fail)
RUN cd native_core && \
    cargo build --release && \
    cp target/release/libpyrph_core.so ../pyrph_core.so && \
    echo "[pyrph] Native core compiled" || \
    echo "[pyrph] Native core build failed - using Python fallback"

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Set PYTHONPATH so imports work regardless of run method
ENV PYTHONPATH=/app

# Verify imports work
RUN python3 -c "import config; from pipeline import ObfuscationPipeline; print('[pyrph] Import check OK')"

CMD ["python", "bot.py"]
