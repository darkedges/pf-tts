FROM pingidentity/pingfederate:2606-13.1.0@sha256:3a74b4d40398202d7f32b029da4d59c73471bad952dec6225ca22f8857fa6be0

ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/darkedges/pf-tts" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.description="PingFederate 13.1 with the reviewed WAI plugin"

ENV SERVER_PROFILE_URL="https://github.com/pingidentity/pingidentity-server-profiles.git" \
    SERVER_PROFILE_PATH="getting-started/pingfederate" \
    SERVER_PROFILE_BRANCH="2606" \
    SERVER_PROFILE_URL_REDACT="true" \
    SERVER_PROFILE_UPDATE="true" \
    PING_IDENTITY_PASSWORD="" \
    SECURITY_CHECKS_STRICT="true"

COPY --chown=9031:0 --chmod=0444 wai-pingfederate-spiffe-plugins.jar /opt/in/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar
