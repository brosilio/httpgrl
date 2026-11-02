# syntax=docker/dockerfile:1
#
# docker build -t httpgrl .                 # native AOT binary on a distroless, non-root base
# docker build --target test .              # run the full test suite (JIT) inside the build
# docker run --rm -p 8080:8080 httpgrl

ARG DOTNET_VERSION=10.0

# ---------------------------------------------------------------- build
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
# Native AOT links with the platform toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ARG TARGETARCH

# Restore layer: only project files, so source edits don't invalidate it.
COPY global.json Directory.Build.props httpgrl.slnx ./
COPY src/Httpgrl.Abstractions/Httpgrl.Abstractions.csproj src/Httpgrl.Abstractions/
COPY src/Httpgrl.Core/Httpgrl.Core.csproj src/Httpgrl.Core/
COPY src/Httpgrl.Modules.StaticFiles/Httpgrl.Modules.StaticFiles.csproj src/Httpgrl.Modules.StaticFiles/
COPY src/Httpgrl.Modules.Rewrite/Httpgrl.Modules.Rewrite.csproj src/Httpgrl.Modules.Rewrite/
COPY src/Httpgrl.Modules.Headers/Httpgrl.Modules.Headers.csproj src/Httpgrl.Modules.Headers/
COPY src/Httpgrl.Modules.Proxy/Httpgrl.Modules.Proxy.csproj src/Httpgrl.Modules.Proxy/
COPY src/Httpgrl/Httpgrl.csproj src/Httpgrl/
COPY tests/Httpgrl.Tests/Httpgrl.Tests.csproj tests/Httpgrl.Tests/
RUN RID=linux-$([ "${TARGETARCH:-amd64}" = "arm64" ] && echo arm64 || echo x64) \
 && dotnet restore src/Httpgrl/Httpgrl.csproj -r "$RID" \
 && dotnet restore tests/Httpgrl.Tests/Httpgrl.Tests.csproj

COPY scripts/ scripts/
COPY src/ src/
COPY conf/ conf/
RUN scripts/check-boundaries.sh \
 && RID=linux-$([ "${TARGETARCH:-amd64}" = "arm64" ] && echo arm64 || echo x64) \
 && dotnet publish src/Httpgrl/Httpgrl.csproj -c Release -r "$RID" --no-restore -o /out \
 && rm -f /out/*.dbg /out/*.pdb \
 && mkdir -p /out/etc/httpgrl \
 && cp conf/docker/httpgrl.conf conf/mime.types /out/etc/httpgrl/ \
 && sed -i 's|/srv/www|/src/conf/html|' /out/etc/httpgrl/httpgrl.conf \
 && /out/httpgrl -t -c /out/etc/httpgrl/httpgrl.conf \
 && cp conf/docker/httpgrl.conf /out/etc/httpgrl/

# ---------------------------------------------------------------- test (opt-in target)
FROM build AS test
COPY tests/ tests/
RUN dotnet run -c Release --project tests/Httpgrl.Tests

# ---------------------------------------------------------------- runtime
# Chiseled = distroless Ubuntu: libc, OpenSSL, CA certificates, a non-root "app" user; no shell, no package manager.
FROM mcr.microsoft.com/dotnet/runtime-deps:${DOTNET_VERSION}-noble-chiseled AS runtime
COPY --from=build /out/httpgrl /app/httpgrl
COPY --from=build /out/etc/httpgrl/ /etc/httpgrl/
COPY conf/html/ /srv/www/
USER app
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/httpgrl"]
CMD ["-c", "/etc/httpgrl/httpgrl.conf"]
