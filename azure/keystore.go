package azure

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
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

	exist, err := bf.blobExist()
	if err != nil {
		return nil, fmt.Errorf("blob file: service unavailable: %w", err)
	}

	if !exist {
		if err := bf.initBlob(); err != nil {
			return nil, fmt.Errorf("blob file: service unavailable: %w", err)
		}
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

	if err := bf.uploadKeys(u, keys, false); err != nil {
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

		decodedSecret, err := base64.RawURLEncoding.DecodeString(ak.Secret)
		if err != nil {
			continue
		}

		keys = append(keys, dataprotection.RotationKey{
			ID:        ak.ID,
			Secret:    decodedSecret,
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})
	}

	return keys, nil
}

func (bf *BlobFile) uploadKeys(u azblob.BlobURL, keys []dataprotection.RotationKey, skipLease bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	leaseID := uuid.New().String()
	azBlobAccessConditions := azblob.BlobAccessConditions{}
	if !skipLease {
		_, err := u.AcquireLease(ctx, leaseID, 60, azblob.ModifiedAccessConditions{})
		if err != nil {
			return fmt.Errorf("blob file: could not lock key file: %w", err)
		}

		azBlobAccessConditions.LeaseAccessConditions = azblob.LeaseAccessConditions{
			LeaseID: leaseID,
		}
	}

	azureKeys := make([]*azureKeyFileFormat, len(keys))
	for _, k := range keys {
		encodedSecret := base64.RawURLEncoding.EncodeToString(k.Secret)

		azureKeys = append(azureKeys, &azureKeyFileFormat{
			ID:        k.ID,
			Secret:    encodedSecret,
			NotBefore: k.NotBefore.Format(time.RFC3339),
			NotAfter:  k.NotAfter.Format(time.RFC3339),
		})
	}

	b, err := json.Marshal(azureKeys)
	if err != nil {
		return fmt.Errorf("blob file: could not serialize JSON: %w", err)
	}

	_, err = u.ToBlockBlobURL().Upload(ctx,
		bytes.NewReader(b),
		azblob.BlobHTTPHeaders{},
		azblob.Metadata{},
		azBlobAccessConditions)
	if err != nil {
		return fmt.Errorf("blob file: failed to upload keys: %w", err)
	}

	if !skipLease {
		_, _ = u.ReleaseLease(ctx, leaseID, azblob.ModifiedAccessConditions{})
	}

	return nil
}

func (bf *BlobFile) blobExist() (bool, error) {
	u, err := bf.blobURL()
	if err != nil {
		return false, err
	}

	_, err = u.GetProperties(context.Background(), azblob.BlobAccessConditions{})

	storageErr, ok := err.(azblob.StorageError)
	if !ok {
		return false, err
	}

	if storageErr.Response().StatusCode == http.StatusNotFound {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return true, nil
}

func (bf *BlobFile) initBlob() error {
	u, err := bf.blobURL()
	if err != nil {
		return err
	}

	return bf.uploadKeys(u, []dataprotection.RotationKey{}, true)
}
