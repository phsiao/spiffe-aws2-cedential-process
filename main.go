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
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var (
	role_arn          string
	role_session_name string
	audience          string
	socket_path       string
	timeout           time.Duration
)

func init() {
	flag.StringVar(&role_arn, "role-arn", "", "ARN of the role to assume")
	flag.StringVar(&role_session_name, "role-session-name", "spiffe-aws2-credential-process", "Role session name to use")
	flag.StringVar(&audience, "audience", "sts.amazonaws.com", "Audience the JWT token will be for")
	flag.StringVar(&socket_path, "socketPath", "unix:/tmp/agent.sock", "Socket path to talk to spiffe agent")
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

	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socket_path))
	jwtSource, err := workloadapi.NewJWTSource(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Unable to create JWTSource: %v", err)
	}
	defer jwtSource.Close()

	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: audience,
	})
	if err != nil {
		log.Fatalf("Unable to fetch SVID: %v", err)
	}

	mySession := session.Must(session.NewSession())
	svc := sts.New(mySession)
	awsCred, err := svc.AssumeRoleWithWebIdentityWithContext(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &role_arn,
		RoleSessionName:  &role_session_name,
		WebIdentityToken: aws.String(svid.Marshal()),
	})
	if err != nil {
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
