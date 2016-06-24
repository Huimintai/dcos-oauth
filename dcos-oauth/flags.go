package main

import "github.com/codegangsta/cli"

var (
	// TODO can we proxy this?
	flIssuerURL = cli.StringFlag{
		Name:   "issuer-url",
		Usage:  "JWT Issuer URL",
		Value:  "https://dcos.auth0.com/",
		EnvVar: "OAUTH_ISSUER_URL",
	}

	flClientID = cli.StringFlag{
		Name:   "client-id",
		Usage:  "JWT Client ID",
		Value:  "3yF5TOSzdlI45Q1xspxzeoGBe9fNxm9m",
		EnvVar: "OAUTH_CLIENT_ID",
	}

	flSecretKeyPath = cli.StringFlag{
		Name:   "secret-key-path",
		Usage:  "Secret key file path",
		Value:  "/var/lib/dcos/auth-token-secret",
		EnvVar: "SECRET_KEY_FILE_PATH",
	}

	flSegmentKey = cli.StringFlag{
		Name:  "segment-key",
		Usage: "Segment key",
		Value: "39uhSEOoRHMw6cMR6st9tYXDbAL3JSaP",
	}

	flKeyStoneURL = cli.StringFlag{
		Name:   "keystone-url",
		Usage:  "KeyStone URL",
		Value:  "http://9.21.62.241:5000/v3",
		EnvVar: "KEYSTONE_URL",
	}

	ksAdminUser = cli.StringFlag{
		Name:   "ks-admin-user",
		Usage:  "ks admin user",
		Value:  "admin",
		EnvVar: "ADMIN",
	}

	ksAdminPassword = cli.StringFlag{
		Name:   "ks-admin-password",
		Usage:  "ks admin password",
		Value:  "admin",
		EnvVar: "ADMIN",
	}

	ksAdminProject = cli.StringFlag{
		Name:   "ks-admin-project",
		Usage:  "ks admin project",
		Value:  "admin",
		EnvVar: "ADMIN",
	}
)
