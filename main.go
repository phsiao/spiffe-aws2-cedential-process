package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	log "github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	REFRESH_HEAD_ROOM = 5 * time.Minute
)

var (
	audience          string
	role_arn          string
	role_session_name string
	socket_path       string
	spiffe_id         string
	timeout           time.Duration
	cache_dir         string
)

func init() {
	flag.StringVar(&audience, "audience", "sts.amazonaws.com", "Audience the JWT token will be for")
	flag.StringVar(&role_arn, "role-arn", "", "ARN of the role to assume")
	flag.StringVar(&role_session_name, "role-session-name", "spiffe-aws2-credential-process", "Role session name to use")
	flag.StringVar(&socket_path, "socketPath", "unix:/tmp/agent.sock", "Socket path to talk to spiffe agent")
	flag.StringVar(&spiffe_id, "spiffe-id", "", "Request a specific SPIFFE ID (instead of all SPIFFE IDs)")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "timeout waiting for the process to finish")
	flag.StringVar(&cache_dir, "cache-dir", "", "cache directory to use for storing the IAM credentials; if set the process would check cache before issuing a new request")
}

type Output struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string
}

type Cache struct {
	Dir string
}

func NewCache(dir string) (*Cache, error) {
	if _, err := os.Open(dir); err != nil {
		return nil, err
	}

	if f, err := os.CreateTemp(dir, "validate-"); err != nil {
		return nil, err
	} else {
		os.Remove(f.Name())
	}

	return &Cache{
		Dir: dir,
	}, nil
}

func (c *Cache) filenameByArguments(role string, aud string, sess string, sid string) (string, error) {
	h := sha256.New()
	// serialization-then-hashing is needed to avoid collisions
	bytes, err := json.Marshal([]string{role, aud, sess, sid})
	if err != nil {
		return "", err
	}
	_, err = h.Write(bytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (c *Cache) Get(role string, aud string, sess string, sid string) (*Output, bool) {
	fn, err := c.filenameByArguments(role, aud, sess, sid)
	if err != nil {
		return nil, false
	}

	fp := path.Join(c.Dir, fn)
	f, err := os.Open(fp)
	if err != nil {
		return nil, false
	}

	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}

	output := Output{}
	err = json.Unmarshal(bytes, &output)
	if err != nil {
		return nil, false
	}

	// check expiration
	if tm, err := time.Parse(time.RFC3339, output.Expiration); err == nil && tm.After(time.Now().Add(REFRESH_HEAD_ROOM)) {
		return &output, true
	}

	// don't use cache
	return nil, false
}

func (c *Cache) Set(role string, aud string, sess string, sid string, output *Output) error {
	fn, err := c.filenameByArguments(role, aud, sess, sid)
	if err != nil {
		return err
	}

	fp := path.Join(c.Dir, fn)
	bytes, err := json.Marshal(output)
	if err != nil {
		return err
	}

	f, err := os.CreateTemp(c.Dir, fn+"-")
	if err != nil {
		return err
	}
	f.Close()

	err = os.WriteFile(f.Name(), bytes, 0600)
	if err != nil {
		os.Remove(f.Name())
		return err
	}

	os.Rename(f.Name(), fp)
	return nil
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

	// try read from cache
	var cache *Cache
	if cache_dir != "" {
		cache, err = NewCache(cache_dir)
		if err != nil {
			log.Warnf("Unable to create cache: %v", err)
		} else {
			if cached, ok := cache.Get(role_arn, audience, role_session_name, spiffe_id); ok {
				output, err := json.MarshalIndent(&cached, "", "  ")
				if err != nil {
					log.Warn(err)
				}
				fmt.Print(string(output))
				return
			}
		}
	}

	mySession := session.Must(session.NewSession())
	svc := sts.New(mySession)
	req, awsCred := svc.AssumeRoleWithWebIdentityRequest(&sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          &role_arn,
		RoleSessionName:  &role_session_name,
		WebIdentityToken: aws.String(svid.Marshal()),
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
		log.Fatalf("Unable to marshal extracted credential: %v", err)
	}

	fmt.Print(string(output))

	// update cache
	if cache != nil {
		if err = cache.Set(role_arn, audience, role_session_name, spiffe_id, &extractedCred); err != nil {
			log.Warnf("Unable to update cache: %v", err)
		}
	}
}
