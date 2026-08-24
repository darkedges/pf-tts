FROM pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0

ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/darkedges/pf-tts" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.description="PingFederate 13.1 with the reviewed WAI plugin" \
      org.opencontainers.image.vendor-profile="https://github.com/pingidentity/pingidentity-server-profiles/tree/50c5d58cb063d742335084d88bff3c2b5fb52cd9/getting-started/pingfederate"

ENV PING_IDENTITY_PASSWORD="" \
    SECURITY_CHECKS_STRICT="true"

ADD --checksum=sha256:16f9a0391b41d304eca2b89c7741053a1c21a8543aeaa6755c91c7b26626c77e --chown=9031:0 --chmod=0444 https://raw.githubusercontent.com/pingidentity/pingidentity-server-profiles/50c5d58cb063d742335084d88bff3c2b5fb52cd9/getting-started/pingfederate/instance/bulk-config/data.json.subst /opt/in/instance/bulk-config/data.json.subst
COPY --chown=9031:0 --chmod=0444 wai-pingfederate-spiffe-plugins.jar /opt/in/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar
