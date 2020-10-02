package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
	"github.com/google/uuid"
	"github.com/ourstudio-se/go-dataprotection"
)

const defaultContainerName = "dataprotection"
const defaultBlobFileName = "data-protection-keys"

type BlobConfig struct {
	accountName string
	credential  azblob.Credential
	container   string
	filename    string
}

type BlobConfigOption func(*BlobConfig) error

func WithCredentials(accountName, accountKey string) BlobConfigOption {
	return func(c *BlobConfig) error {
		credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
		if err != nil {
			return err
		}

		c.accountName = accountName
		c.credential = credential
		return nil
	}
}

func WithContainer(containerName string) BlobConfigOption {
	return func(c *BlobConfig) error {
		if containerName == "" {
			return errors.New("blob config: missing container name")
		}

		c.container = containerName
		return nil
	}
}

func WithFile(fileName string) BlobConfigOption {
	return func(c *BlobConfig) error {
		if fileName == "" {
			return errors.New("blob config: missing filename")
		}

		c.filename = fileName
		return nil
	}
}

type BlobFile struct {
	cfg  *BlobConfig
	keys []dataprotection.RotationKey
}

type azureKeyFileFormat struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

func WithBlob(opts ...BlobConfigOption) dataprotection.ProtectorOption {
	return func(p *dataprotection.Protector) error {
		bf, err := New(opts...)
		if err != nil {
			return fmt.Errorf("azure blob file: %w", err)
		}

		cb := dataprotection.WithBackend(bf)
		return cb(p)
	}
}

func New(opts ...BlobConfigOption) (*BlobFile, error) {
	cfg := &BlobConfig{}
	cfg.container = defaultContainerName
	cfg.filename = defaultBlobFileName

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("blob config: %w", err)
		}
	}

	if cfg.credential == nil {
		return nil, errors.New("blob config: missing credentials")
	}

	bf := &BlobFile{cfg, nil}
	u, err := bf.containerURL()
	if err != nil {
		return nil, fmt.Errorf("blob file: container error: %w", err)
	}

	_, _ = u.Create(context.Background(), azblob.Metadata{}, azblob.PublicAccessNone)
	return bf, nil
}

func (bf *BlobFile) GetKeys() ([]dataprotection.RotationKey, error) {
	u, err := bf.blobURL()
	if err != nil {
		return nil, fmt.Errorf("blob file: failed connecting to blob: %w", err)
	}

	keys, err := bf.downloadKeys(u)
	if err != nil {
		return nil, err
	}

	bf.keys = keys
	return keys, nil
}

func (bf *BlobFile) AddKey(key dataprotection.RotationKey) error {
	keys := append(bf.keys, key)

	u, err := bf.blobURL()
	if err != nil {
		return fmt.Errorf("blob file: failed connecting to blob: %w", err)
	}

	if err := bf.uploadKeys(u, keys); err != nil {
		return err
	}

	bf.keys = keys
	return nil
}

func (bf *BlobFile) containerURL() (azblob.ContainerURL, error) {
	p := azblob.NewPipeline(bf.cfg.credential, azblob.PipelineOptions{})
	u, err := url.Parse(fmt.Sprintf("https://%s.blob.core.windows.net/%s", bf.cfg.accountName, bf.cfg.container))
	if err != nil {
		return azblob.ContainerURL{}, err
	}

	return azblob.NewContainerURL(*u, p), nil
}

func (bf *BlobFile) blobURL() (azblob.BlobURL, error) {
	u, err := bf.containerURL()
	if err != nil {
		return azblob.BlobURL{}, err
	}

	return u.NewBlobURL(bf.cfg.filename), nil
}

func (bf *BlobFile) downloadKeys(u azblob.BlobURL) ([]dataprotection.RotationKey, error) {
	r, err := u.Download(context.Background(), 0, azblob.CountToEnd, azblob.BlobAccessConditions{}, false)
	if err != nil {
		return []dataprotection.RotationKey{}, nil
	}

	stream := r.Body(azblob.RetryReaderOptions{MaxRetryRequests: 3})
	buf := bytes.Buffer{}
	_, err = buf.ReadFrom(stream)
	if err != nil {
		return nil, fmt.Errorf("blob file: reading file failed: %w", err)
	}

	var azureKeys []*azureKeyFileFormat
	if err := json.Unmarshal(buf.Bytes(), &azureKeys); err != nil {
		return nil, fmt.Errorf("blob file: unmarshalling file failed: %w", err)
	}

	var keys []dataprotection.RotationKey
	for _, ak := range azureKeys {
		notBefore, err := time.Parse(time.RFC3339, ak.NotBefore)
		if err != nil {
			continue
		}

		notAfter, err := time.Parse(time.RFC3339, ak.NotAfter)
		if err != nil {
			continue
		}

		keys = append(keys, dataprotection.RotationKey{
			ID:        ak.ID,
			Secret:    []byte(ak.Secret),
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})
	}

	return keys, nil
}

func (bf *BlobFile) uploadKeys(u azblob.BlobURL, keys []dataprotection.RotationKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	leaseID := uuid.New().String()
	_, err := u.AcquireLease(ctx, leaseID, 60, azblob.ModifiedAccessConditions{})
	if err != nil {
		return fmt.Errorf("blob file: could not lock key file: %w", err)
	}

	var azureKeys []*azureKeyFileFormat
	for _, k := range bf.keys {
		azureKeys = append(azureKeys, &azureKeyFileFormat{
			ID:        k.ID,
			Secret:    string(k.Secret),
			NotBefore: k.NotBefore.Format(time.RFC3339),
			NotAfter:  k.NotAfter.Format(time.RFC3339),
		})
	}

	b, err := json.Marshal(azureKeys)
	if err != nil {
		return fmt.Errorf("blob file: could not serialize JSON: %w", err)
	}

	_, err = u.ToBlockBlobURL().Upload(ctx, bytes.NewReader(b), azblob.BlobHTTPHeaders{}, azblob.Metadata{}, azblob.BlobAccessConditions{})
	if err != nil {
		return fmt.Errorf("blob file: failed to upload keys: %w", err)
	}

	_, _ = u.ReleaseLease(ctx, leaseID, azblob.ModifiedAccessConditions{})

	return nil
}
