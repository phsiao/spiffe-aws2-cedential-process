package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	audience          string
	role_arn          string
	role_session_name string
	socket_path       string
	spiffe_id         string
	session_duration  time.Duration
	timeout           time.Duration
)

func init() {
	flag.StringVar(&audience, "audience", "sts.amazonaws.com", "Audience the JWT token will be for")
	flag.StringVar(&role_arn, "role-arn", "", "ARN of the role to assume")
	flag.StringVar(&role_session_name, "role-session-name", "spiffe-aws2-credential-process", "Role session name to use")
	flag.StringVar(&socket_path, "socketPath", "unix:/tmp/agent.sock", "Socket path to talk to spiffe agent")
	flag.StringVar(&spiffe_id, "spiffe-id", "", "Request a specific SPIFFE ID (instead of all SPIFFE IDs)")
	flag.DurationVar(&session_duration, "session-duration", 3600*time.Second, "The duration, in seconds, of the role session.")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "timeout waiting for the process to finish")
}

type Output struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	params := jwtsvid.Params{
		Audience: audience,
	}
	if len(spiffe_id) > 0 {
		subject, err := spiffeid.FromString(spiffe_id)
		if err != nil {
			log.Fatalf("Unable to parse SPIFFE ID: %s", spiffe_id)
		} else {
			params.Subject = subject
		}
	}

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socket_path))
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	svid, err := jwtSource.FetchJWTSVID(ctx, params)
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	mySession := session.Must(session.NewSession())
	svc := sts.New(mySession)
	req, awsCred := svc.AssumeRoleWithWebIdentityRequest(&sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &role_arn,
		RoleSessionName:  &role_session_name,
		WebIdentityToken: aws.String(svid.Marshal()),
		DurationSeconds:  aws.Int64(int64(session_duration.Seconds())),
	})
	req.SetContext(ctx)
	// InvalidIdentityToken error is a temporary error that can occur
	// when assuming an Role with a JWT web identity token.
	req.RetryErrorCodes = append(req.RetryErrorCodes, sts.ErrCodeInvalidIdentityTokenException)
	if err := req.Send(); err != nil {
		log.Fatalf("Unable to perform assume-role-with-web-identity: %v", err)
	}

	extractedCred := Output{
		Version:         1,
		AccessKeyId:     *awsCred.Credentials.AccessKeyId,
		SecretAccessKey: *awsCred.Credentials.SecretAccessKey,
		SessionToken:    *awsCred.Credentials.SessionToken,
		Expiration:      awsCred.Credentials.Expiration.Format(time.RFC3339),
	}

	output, err := json.MarshalIndent(&extractedCred, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(output))
}
