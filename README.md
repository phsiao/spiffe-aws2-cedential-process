# Integrate Spiffe and AWS credential-process

To use the spiffe token in AWS CLI/library, one is required
to fetch the token and put that into a file for AWS CLI/library
to consume.

This small utility simplifies the process by using the
`credential-process` configuration.

# Example

Before one would need to configure their `.aws/config` like this

```
[profile default]
role_arn = arn:aws:iam::123456789012:role/my-role
web_identity_token_file = /var/tmp/spiffe.creds.jwt
```

and have a process to periodically update the content of
`/var/tmp/spiffe.creds.jwt` with a valid token.

Here we can simplify it to be

```
[profile default]
credential_process = spiffe-aws2-credential-process --role-arn arn:aws:iam::123456789012:role/my-role
```

# Installation

```
# go get github.com/phsiao/spiffe-aws2-credential-process
```

The current supported options and their defaults are:

```
  -audience string
    	Audience the JWT token will be for (default "sts.amazonaws.com")
  -cache-dir string
    	cache directory to use for storing the IAM credentials; if set the process would check cache before issuing a new request
  -role-arn string
    	ARN of the role to assume
  -role-session-name string
    	Role session name to use (default "spiffe-aws2-credential-process")
  -socketPath string
    	Socket path to talk to spiffe agent (default "unix:/tmp/agent.sock")
  -spiffe-id string
    	Request a specific SPIFFE ID (instead of all SPIFFE IDs)
  -timeout duration
    	timeout waiting for the process to finish (default 10s)
```

# AWS IAM Credential Cache

When performing an `assume-role-with-web-identity` operation, the
AWS Security Token Service (STS) must retrieve signing keys for Spiffe ID
verification, which can cause problems when making frequent requests. This is
because the STS service fetches the keys every time it's called if the keys
are not cached, and it has a low request limit that can lead to errors like this:

```
Unable to perform assume-role-with-web-identity: InvalidIdentityToken: Couldn't retrieve verification key from your identity provider,  please reference AssumeRoleWithWebIdentity documentation for requirements\n\tstatus code: 400
```

If you specify the -cache-dir argument, the command will cache the STS token
in the directory you specified. It will store the STS token in a local file
and use it instead of making a new call to AWS STS service in future invocations.
The token stored on the file system is at risk if unauthorized access happens.

Note that the command will treat a token as expired _5 minutes_ before its
actual expiration time to allow the process to function without having to
immediately deal with expired token.
