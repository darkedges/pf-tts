# Task 50 implementation notes

## Acceptance criteria restatement

Task 50 builds and tests the repository plugin against the reviewed PingFederate
13.1 SDK boundary, then packages only the plugin JAR and public startup hook in a
minimal OCI artifact. The artifact must contain no product, SDK, runtime library,
secret, certificate, key, license, export, Terraform input/state, symlink, or
unexpected writable file. Publication requires a clean Git revision, immutable
tagging input, and produces a registry digest for deployment pinning.

## Implementation

- `scripts/build-pingfederate-profile-artifact.ps1` invokes the existing pinned
  SDK build and its Java tests before creating a random, bounded build context.
- The context and exported root filesystem are both compared with exact
  allowlists. Any additional or missing path fails the build.
- `deploy/pingfederate/profile-artifact/Dockerfile` uses `scratch`, copies the
  two allowed files explicitly, and sets both file modes to `0444`.
- The builder rejects symlinks, non-regular inputs, private-key markers, literal
  credential assignments, dirty publication trees, and mutable `latest` tags.
- Validation exports the built filesystem to a temporary tar and inventories it
  without starting a container. Publication uses a pinned source revision and
  multi-platform BuildKit push; the resulting registry digest is the deployment
  identity recorded in Task 55.

## Trust boundaries and failure cases

The repository source and locally extracted, version-checked SDK are build
inputs. Neither is trusted merely because it is present: the existing profile
builder verifies the exact SDK version and required classes, while the artifact
builder admits only the generated JAR and reviewed public hook. The entire
working tree is outside the release trust boundary until Git reports it clean.

The OCI registry tag is a publication locator, not an immutable deployment
identity. Kubernetes must consume the manifest digest captured after publishing.
No registry credential crosses into the build context or image.

Failure tests cover broad directory copies, product/SDK references, secret
inputs, private-key markers, credential assignments, symlinks, dirty-tree
publication, mutable tags, unexpected context/output paths, and writable
allowlisted files. Validation is fail-closed; no content or identity check is
relaxed to accommodate an artifact.

## Operational commands

`make pf-profile-artifact` builds, inventories, and validates locally.

`make pf-profile-artifact-push PF_PROFILE_ARTIFACT_IMAGE=<registry>/<name>:<commit>`
publishes from a clean commit. Record the returned manifest digest and use that
digest, rather than the tag, in deployment values.
