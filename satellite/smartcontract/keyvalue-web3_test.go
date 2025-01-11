package smartcontract

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyValueWeb3Helper(t *testing.T) {
	ctx := context.Background()

	config := Web3Config{}

	t.Run("New KeyValue Web3 Helper", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config)
		require.NoError(t, err)
		require.NotNil(t, helper)
		require.NotNil(t, helper.web3Helper)
	})

	t.Run("Upload and Get Social Share", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config)
		require.NoError(t, err)

		testID := "test-id-123"
		testData := "test social share data"

		// Test Upload
		err = helper.UploadSocialShare(ctx, testID, testData)
		require.NoError(t, err)

		// Test Get
		retrievedData, err := helper.GetSocialShare(ctx, testID)
		require.NoError(t, err)
		require.Equal(t, testData, retrievedData)
	})

	t.Run("Update Existing Social Share", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config)
		require.NoError(t, err)

		testID := "test-id-456"
		initialData := "initial data"
		updatedData := "updated data"

		// Upload initial data
		err = helper.UploadSocialShare(ctx, testID, initialData)
		require.NoError(t, err)

		// Update with new data
		err = helper.UploadSocialShare(ctx, testID, updatedData)
		require.NoError(t, err)

		// Verify update
		retrievedData, err := helper.GetSocialShare(ctx, testID)
		require.NoError(t, err)
		require.Equal(t, updatedData, retrievedData)
	})

	t.Run("Get Non-Existent Key", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config)
		require.NoError(t, err)

		_, err = helper.GetSocialShare(ctx, "non-existent-key")
		require.Error(t, err)
	})

	t.Run("Nil Web3 Helper", func(t *testing.T) {
		var helper *keyValueWeb3Helper

		err := helper.UploadSocialShare(ctx, "test", "test")
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")

		_, err = helper.GetSocialShare(ctx, "test")
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")
	})
}

func TestKeyValueWeb3HelperMock(t *testing.T) {
	ctx := context.Background()
	mockData := make(map[string]string)

	// Create a mock implementation
	mock := &mockKeyValueWeb3Helper{data: mockData}

	t.Run("Mock Upload and Get", func(t *testing.T) {
		testID := "test-id"
		testData := []byte("test data")

		err := mock.UploadSocialShare(ctx, testID, testData)
		require.NoError(t, err)

		retrieved, err := mock.GetSocialShare(ctx, testID)
		require.NoError(t, err)
		require.Equal(t, testData, retrieved)
	})
}

// Mock implementation for testing
type mockKeyValueWeb3Helper struct {
	data map[string]string
}

func (m *mockKeyValueWeb3Helper) UploadSocialShare(ctx context.Context, id string, share []byte) error {
	m.data[id] = string(share)
	return nil
}

func (m *mockKeyValueWeb3Helper) GetSocialShare(ctx context.Context, id string) ([]byte, error) {
	if value, ok := m.data[id]; ok {
		return []byte(value), nil
	}
	return nil, fmt.Errorf("key not found")
}
