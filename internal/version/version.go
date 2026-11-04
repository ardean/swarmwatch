// Package version holds the release version, set at build time with
// -ldflags "-X github.com/ardean/swarmwatch/internal/version.Version=0.3.0".
package version

// Version is "dev" for a build that was not made from a release.
var Version = "dev"
