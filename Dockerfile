FROM python:3.11-slim

# Install build deps for Rust
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl build-essential pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Rust (stable, minimal)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . .

# Compile Rust native core → pyrph_core.so
RUN cd native_core && \
    cargo build --release && \
    cp target/release/libpyrph_core.so ../pyrph_core.so && \
    echo "[pyrph] Native core compiled: $(du -h ../pyrph_core.so | cut -f1)"

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Verify native bridge loads
RUN python3 -c "from native_bridge import status; print(status())"

CMD ["python", "bot.py"]
