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

	fn := path.Join(dir, "validate")
	if _, err := os.Create(fn); err != nil {
		return nil, err
	} else {
		os.Remove(fn)
	}

	return &Cache{
		Dir: dir,
	}, nil
}

func (c *Cache) filenameByRole(role string) string {
	h := sha256.New()
	h.Write([]byte(role))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (c *Cache) Get(role string) (*Output, bool) {
	fn := path.Join(c.Dir, c.filenameByRole(role))
	if f, err := os.Open(fn); err != nil {
		return nil, false
	} else {
		if bytes, err := io.ReadAll(f); err != nil {
			return nil, false
		} else {
			output := Output{}
			if err := json.Unmarshal(bytes, &output); err != nil {
				return nil, false
			} else {
				// check expiration
				if tm, err := time.Parse(time.RFC3339, output.Expiration); err == nil && tm.After(time.Now().Add(REFRESH_HEAD_ROOM)) {
					return &output, true
				} else {
					// don't use cache
					return nil, false
				}
			}
		}
	}
}

func (c *Cache) Set(role string, output *Output) error {
	fn := path.Join(c.Dir, c.filenameByRole(role))
	if bytes, err := json.Marshal(output); err != nil {
		return err
	} else {
		if err := os.WriteFile(fn, bytes, 0600); err != nil {
			return err
		} else {
			return nil
		}
	}
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
	if cache_dir != "" {
		if cache, err := NewCache(cache_dir); err != nil {
			log.Warnf("Unable to create cache: %v", err)
		} else {
			if cached, ok := cache.Get(role_arn); ok {
				output, err := json.MarshalIndent(&cached, "", "  ")
				if err != nil {
					log.Warn(err)
				}
				fmt.Print(string(output))
				os.Exit(0)
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
	if cache_dir != "" {
		if cache, err := NewCache(cache_dir); err == nil {
			if err := cache.Set(role_arn, &extractedCred); err != nil {
				log.Warn(err)
			}
		}
	}
}
