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
	role_arn    string
	audience    string
	socket_path string
)

func init() {
	flag.StringVar(&role_arn, "role-arn", "", "ARN of the role to assume")
	flag.StringVar(&audience, "audience", "sts.amazonaws.com", "Audience the JWT token will be for")
	flag.StringVar(&socket_path, "socketPath", "/tmp/agent.sock", "Socket path to talk to spiffe agent")
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

	ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
	clientOptions := workloadapi.WithClientOptions(workloadapi.WithAddr(socket_path))
	// Create a JWTSource to fetch JWT-SVIDs
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
	awsCred, err := svc.AssumeRoleWithWebIdentity(&sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &role_arn,
		RoleSessionName:  aws.String("spiffe-aws2-wrap"),
		WebIdentityToken: aws.String(svid.Marshal()),
	})
	if err != nil {
		log.Fatalf("Unable to perform assume-role-with-web-identity: %v", err)
	}

	log.Info(awsCred)
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
