FROM scratch
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="WAI PingFederate public profile artifact" \
      org.opencontainers.image.description="Repository-owned PingFederate plugin and public profile hook only" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
COPY --chmod=0444 profile/hooks/02-get-remote-server-profile.sh.post /profile/hooks/02-get-remote-server-profile.sh.post
COPY --chmod=0444 profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar /profile/instance/server/default/deploy/wai-pingfederate-spiffe-plugins.jar
