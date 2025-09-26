package azure

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/lease"
	"github.com/google/uuid"
	"github.com/ourstudio-se/go-dataprotection"
)

const (
	defaultContainerName = "dataprotection"
	defaultBlobFileName  = "data-protection-keys"
)

type BlobConfig struct {
	accountName string
	credential  *azblob.SharedKeyCredential
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

	// Create container if it doesn't exist
	containerClient, err := bf.containerClient()
	if err != nil {
		return nil, fmt.Errorf("blob file: failed to create client: %w", err)
	}
	_, _ = containerClient.Create(context.Background(), nil)

	exist, err := bf.blobExist()
	if err != nil {
		return nil, fmt.Errorf("blob file: service unavailable: %w", err)
	}

	if !exist {
		if err := bf.initBlob(); err != nil {
			return nil, fmt.Errorf("blob file: service unavailable: %w", err)
		}
	}

	return bf, nil
}

func (bf *BlobFile) GetKeys() ([]dataprotection.RotationKey, error) {
	keys, err := bf.downloadKeys()
	if err != nil {
		return nil, err
	}

	bf.keys = keys
	return keys, nil
}

func (bf *BlobFile) AddKey(key dataprotection.RotationKey) error {
	keys := append(bf.keys, key)

	if err := bf.uploadKeys(keys, false); err != nil {
		return err
	}

	bf.keys = keys
	return nil
}

func (bf *BlobFile) client() (*azblob.Client, error) {
	serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net/", bf.cfg.accountName)
	client, err := azblob.NewClientWithSharedKeyCredential(serviceURL, bf.cfg.credential, nil)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (bf *BlobFile) containerClient() (*container.Client, error) {
	client, err := bf.client()
	if err != nil {
		return nil, err
	}
	return client.ServiceClient().NewContainerClient(bf.cfg.container), nil
}

func (bf *BlobFile) blobClient() (*blob.Client, error) {
	containerClient, err := bf.containerClient()
	if err != nil {
		return nil, err
	}
	return containerClient.NewBlobClient(bf.cfg.filename), nil
}

func (bf *BlobFile) downloadKeys() ([]dataprotection.RotationKey, error) {
	blobClient, err := bf.blobClient()
	if err != nil {
		return nil, fmt.Errorf("blob file: failed to create client: %w", err)
	}

	resp, err := blobClient.DownloadStream(context.Background(), nil)
	if err != nil {
		// Return empty list if blob doesn't exist
		if bloberror.HasCode(err, bloberror.BlobNotFound) {
			return []dataprotection.RotationKey{}, nil
		}
		return nil, fmt.Errorf("blob file: failed to download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("blob file: reading file failed: %w", err)
	}

	var azureKeys []*azureKeyFileFormat
	if err := json.Unmarshal(data, &azureKeys); err != nil {
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

func (bf *BlobFile) uploadKeys(keys []dataprotection.RotationKey, skipLease bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	blobClient, err := bf.blobClient()
	if err != nil {
		return fmt.Errorf("blob file: failed to create client: %w", err)
	}

	var leaseID *string
	var blobLeaseClient *lease.BlobClient

	if !skipLease {
		// Acquire lease
		leaseUUID := uuid.New().String()
		leaseID = &leaseUUID
		blobLeaseClient, _ = lease.NewBlobClient(blobClient, &lease.BlobClientOptions{
			LeaseID: leaseID,
		})

		if blobLeaseClient != nil {
			_, err := blobLeaseClient.AcquireLease(ctx, 60, nil)
			if err != nil {
				// If we can't acquire a lease, it might be because the blob doesn't exist yet
				// In that case, we'll create it without a lease
				if !bloberror.HasCode(err, bloberror.BlobNotFound) {
					return fmt.Errorf("blob file: could not lock key file: %w", err)
				}
				leaseID = nil
			}
		}
	}

	azureKeys := []*azureKeyFileFormat{}
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

	// Upload blob
	uploadOptions := &azblob.UploadBufferOptions{}
	if leaseID != nil {
		uploadOptions.AccessConditions = &blob.AccessConditions{
			LeaseAccessConditions: &blob.LeaseAccessConditions{
				LeaseID: leaseID,
			},
		}
	}

	client, err := bf.client()
	if err != nil {
		return fmt.Errorf("blob file: failed to create client: %w", err)
	}
	_, err = client.UploadBuffer(ctx, bf.cfg.container, bf.cfg.filename, b, uploadOptions)
	if err != nil {
		return fmt.Errorf("blob file: failed to upload keys: %w", err)
	}

	if leaseID != nil && blobLeaseClient != nil {
		_, _ = blobLeaseClient.ReleaseLease(ctx, nil)
	}

	return nil
}

func (bf *BlobFile) blobExist() (bool, error) {
	blobClient, err := bf.blobClient()
	if err != nil {
		return false, fmt.Errorf("blob file: failed to create client: %w", err)
	}

	_, err = blobClient.GetProperties(context.Background(), nil)
	if err == nil {
		return true, nil
	}

	if bloberror.HasCode(err, bloberror.BlobNotFound) {
		return false, nil
	}

	return false, err
}

func (bf *BlobFile) initBlob() error {
	return bf.uploadKeys([]dataprotection.RotationKey{}, true)
}
