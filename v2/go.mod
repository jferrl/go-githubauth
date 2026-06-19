module github.com/jferrl/go-githubauth/v2

go 1.25.0

// The /v2 module path was published by accident. Use github.com/jferrl/go-githubauth (v1.x) instead.
retract (
	v2.0.0 // Accidental release. Use v1.x instead.
	v2.0.1 // Retraction-only release; superseded by v2.0.2.
	v2.0.2 // Retraction-only release. Use v1.x instead.
)
