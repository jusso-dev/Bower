# AWS Emulator (https://github.com/aws/aws-emulator) for tests/e2e/aws-emulator.sh only.
# AWS publishes no image, so this installs the signed Linux package. The version and
# base image are pinned; the package signature is checked against the AWS publishing
# key fingerprint from the emulator user guide before installation.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:61cf86a8168c2e0b8fc6b6badaac64968044c947718508d88fac06e61a596e6d
ARG TARGETARCH
ARG AWS_EMULATOR_VERSION=1.0.322
ARG AWS_PUBLISHING_FINGERPRINT=98BCF336A3BE53B734E967C52E5BF49BD940F624
RUN set -eu; \
    arch="$([ "$TARGETARCH" = arm64 ] && echo aarch64 || echo x86_64)"; \
    package="aws-emulator-${AWS_EMULATOR_VERSION}-1-${arch}.rpm"; \
    base=https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS; \
    cd /tmp; \
    curl -fsSLo "$package" "$base/$package"; \
    curl -fsSLo "$package.sig" "$base/$package.sig"; \
    curl -fsSLo aws-publishing.asc https://downloads.aws.com/keys/gpg/current.asc; \
    export GNUPGHOME=/tmp/gnupg; mkdir -m 700 "$GNUPGHOME"; \
    # The minimal image has no gpg-agent, so --import exits 2 after a successful public
    # key import; the fingerprint and VALIDSIG checks below are what gate installation.
    gpg --batch --quiet --import aws-publishing.asc 2>/dev/null || true; \
    gpg --batch --with-colons --fingerprint | grep -q "^fpr:::::::::${AWS_PUBLISHING_FINGERPRINT}:"; \
    gpg --batch --status-fd 1 --verify "$package.sig" "$package" 2>/dev/null \
        | grep -Eq "^\[GNUPG:\] VALIDSIG ${AWS_PUBLISHING_FINGERPRINT} .* ${AWS_PUBLISHING_FINGERPRINT}\$"; \
    rpm -i "$package"; \
    rm -rf /tmp/*; \
    mkdir -p /home/emulator && chown 1000 /home/emulator
USER 1000
ENV HOME=/home/emulator \
    EMULATOR_TELEMETRY=off
# Default bind is 127.0.0.1: the e2e clients share this container's network namespace,
# so no port is published and nothing outside the namespace can reach the emulator.
ENTRYPOINT ["aws-emulator", "--telemetry", "off"]
