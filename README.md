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
credentail_process = spiffe-aws-credential-process --role-arn arn:aws:iam::123456789012:role/my-role
```

# Installation

```
# go get github.com/phsiao/spiffe-aws2-credential-process
```

The current supported options and their defaults are:

```
  -audience string
        Audience the JWT token will be for (default "sts.amazonaws.com")
  -role-arn string
        ARN of the role to assume
  -role-session-name string
        Role session name to use (default "spiffe-aws2-credential-process")
  -socketPath string
        Socket path to talk to spiffe agent (default "unix:/tmp/agent.sock")
```
