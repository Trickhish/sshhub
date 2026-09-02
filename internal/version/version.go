package version

// Version is the current release version of sshhub and sshhub-agent.
//
// It is overridden at build time by the release workflow via:
//
//	-ldflags "-X github.com/Trickhish/sshhub/internal/version.Version=<tag>"
//
// It must therefore be a var, not a const: -X cannot patch a constant. The
// fallback below is what locally built (unreleased) binaries report.
var Version = "0.6.0"
