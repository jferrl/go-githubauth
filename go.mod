module github.com/jferrl/go-githubauth

go 1.25

// Retract v2.0.0 due to versioning error; use v1.x.x instead
retract v2.0.0

require (
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/google/go-github/v73 v73.0.0
	golang.org/x/oauth2 v0.30.0
)

require (
	github.com/gorilla/mux v1.8.1 // indirect
	golang.org/x/time v0.12.0 // indirect
)

require (
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/migueleliasweb/go-github-mock v1.4.0
)
