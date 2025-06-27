package smartcontract

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKeyValueWeb3Helper(t *testing.T) {
	ctx := context.Background()

	privateKey := "3005822d22ae044a3c83683fcdb199fbf5bcbcabc95f2fc8e1b212fe3b7c7710"
	config := Web3Config{
		Address:      "0x29a2F6D5b749b5882DfE866772d656FCaae63E0D",
		NetworkRPC:   "https://erpc.xinfin.network",
		ContractAddr: "0x8E589D1E3d0F4189cbFe05703dE840678e402ffC",
	}

	t.Run("New KeyValue Web3 Helper", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config, privateKey)
		require.NoError(t, err)
		require.NotNil(t, helper)
		require.NotNil(t, helper.web3Helper)
	})

	t.Run("Upload and Get Social Share with Version", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config, privateKey)
		require.NoError(t, err)

		testCases := []struct {
			name      string
			id        string
			share     string
			versionId string
			wantErr   bool
		}{
			{
				name:      "Basic Upload and Retrieve",
				id:        fmt.Sprintf("test-id-%d", time.Now().UnixNano()),
				share:     "test social share data",
				versionId: "v1",
				wantErr:   false,
			},
			{
				name:      "Update Existing Share",
				id:        fmt.Sprintf("test-id-%d", time.Now().UnixNano()),
				share:     "initial data",
				versionId: "v1",
				wantErr:   false,
			},
			{
				name:      "Empty Version ID",
				id:        fmt.Sprintf("test-id-%d", time.Now().UnixNano()),
				share:     "test data",
				versionId: "",
				wantErr:   true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Test Upload
				err := helper.UploadSocialShare(ctx, tc.id, tc.share, tc.versionId)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)

				// Test Get
				retrievedData, err := helper.GetSocialShare(ctx, tc.id, tc.versionId)
				require.NoError(t, err)
				require.Equal(t, tc.share, string(retrievedData))

				if tc.name == "Update Existing Share" {
					// Test Update
					updatedShare := "updated data"
					updatedVersion := "v2"
					err = helper.UpdateSocialShare(ctx, tc.id, updatedShare, updatedVersion)
					require.NoError(t, err)

					// Verify both versions
					v1Data, err := helper.GetSocialShare(ctx, tc.id, tc.versionId)
					require.NoError(t, err)
					require.Equal(t, tc.share, string(v1Data))

					v2Data, err := helper.GetSocialShare(ctx, tc.id, updatedVersion)
					require.NoError(t, err)
					require.Equal(t, updatedShare, string(v2Data))
				}
			})
		}
	})

	t.Run("Pagination and Total Keys", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config, privateKey)
		require.NoError(t, err)

		// Setup test data
		// testData := []struct {
		// 	id        string
		// 	share     string
		// 	versionId string
		// }{
		// 	{fmt.Sprintf("test-id-1-%d", time.Now().UnixNano()), "data1", "v1"},
		// 	{fmt.Sprintf("test-id-2-%d", time.Now().UnixNano()), "data2", "v1"},
		// 	{fmt.Sprintf("test-id-3-%d", time.Now().UnixNano()), "data3", "v1"},
		// 	{fmt.Sprintf("test-id-4-%d", time.Now().UnixNano()), "data4", "v1"},
		// 	{fmt.Sprintf("test-id-5-%d", time.Now().UnixNano()), "data5", "v1"},
		// }

		// // Upload test data
		// for _, td := range testData {
		// 	err := helper.UploadSocialShare(ctx, td.id, td.share, td.versionId)
		// 	require.NoError(t, err)
		// }

		// // Test GetTotalKeys
		// total, err := helper.GetTotalKeys(ctx)
		// require.NoError(t, err)
		// require.GreaterOrEqual(t, total, uint64(len(testData)))

		// Test pagination
		testCases := []struct {
			name       string
			startIndex uint64
			count      uint64
			wantCount  int
			wantErr    bool
		}{
			{
				name:       "First Page",
				startIndex: 0,
				count:      3,
				wantCount:  3,
				wantErr:    false,
			},
			{
				name:       "Second Page",
				startIndex: 3,
				count:      2,
				wantCount:  2,
				wantErr:    false,
			},
			{
				name: "Invalid Start Index",
				// startIndex: total + 1,
				count:     1,
				wantCount: 0,
				wantErr:   true,
			},
			{
				name:       "Zero Count",
				startIndex: 0,
				count:      0,
				wantCount:  0,
				wantErr:    true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				keys, values, versions, err := helper.GetPaginatedKeyValues(ctx, 1, tc.count)
				if tc.wantErr {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.wantCount, len(keys))
				require.Equal(t, len(keys), len(values))
				require.Equal(t, len(keys), len(versions))
			})
		}
	})

	t.Run("Get Non-Existent Key", func(t *testing.T) {
		helper, err := NewKeyValueWeb3Helper(config, privateKey)
		require.NoError(t, err)

		data, err := helper.GetSocialShare(ctx, "non-existent-key", "v1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key or version not found")
		require.Nil(t, data)
	})

	t.Run("Nil Web3 Helper", func(t *testing.T) {
		var helper *keyValueWeb3Helper

		err := helper.UploadSocialShare(ctx, "test", "test", "v1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")

		_, err = helper.GetSocialShare(ctx, "test", "v1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")

		_, _, _, err = helper.GetPaginatedKeyValues(ctx, 0, 10)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")

		_, err = helper.GetTotalKeys(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web3Helper is nil")
	})
}

// Mock implementation for testing
type mockKeyValueWeb3Helper struct {
	data map[string]map[string]string // map[id]map[versionId]share
}

func (m *mockKeyValueWeb3Helper) UploadSocialShare(ctx context.Context, id string, share string, versionId string) error {
	if m.data == nil {
		m.data = make(map[string]map[string]string)
	}
	if m.data[id] == nil {
		m.data[id] = make(map[string]string)
	}
	m.data[id][versionId] = share
	return nil
}

func (m *mockKeyValueWeb3Helper) UpdateSocialShare(ctx context.Context, id string, share string, versionId string) error {
	return m.UploadSocialShare(ctx, id, share, versionId)
}

func (m *mockKeyValueWeb3Helper) GetSocialShare(ctx context.Context, id string, versionId string) ([]byte, error) {
	if m.data == nil || m.data[id] == nil {
		return nil, fmt.Errorf("key not found")
	}
	if share, ok := m.data[id][versionId]; ok {
		return []byte(share), nil
	}
	return nil, fmt.Errorf("version not found")
}

func (m *mockKeyValueWeb3Helper) GetPaginatedKeyValues(ctx context.Context, startIndex, count uint64) (keys, values, versionIds []string, err error) {
	if startIndex >= uint64(len(m.data)) {
		return nil, nil, nil, fmt.Errorf("invalid start index")
	}
	if count == 0 {
		return nil, nil, nil, fmt.Errorf("invalid count")
	}
	return []string{}, []string{}, []string{}, nil
}

func (m *mockKeyValueWeb3Helper) GetTotalKeys(ctx context.Context) (uint64, error) {
	return uint64(len(m.data)), nil
}

func TestKeyValueWeb3HelperMock(t *testing.T) {
	ctx := context.Background()
	mockData := make(map[string]map[string]string)
	mock := &mockKeyValueWeb3Helper{data: mockData}

	t.Run("Mock Upload and Get with Versions", func(t *testing.T) {
		testID := "test-id"
		testShare := "test data"
		testVersion := "v1"

		err := mock.UploadSocialShare(ctx, testID, testShare, testVersion)
		require.NoError(t, err)

		retrieved, err := mock.GetSocialShare(ctx, testID, testVersion)
		require.NoError(t, err)
		require.Equal(t, testShare, string(retrieved))

		// Test version update
		updatedShare := "updated data"
		updatedVersion := "v2"
		err = mock.UpdateSocialShare(ctx, testID, updatedShare, updatedVersion)
		require.NoError(t, err)

		// Check both versions exist
		v1Data, err := mock.GetSocialShare(ctx, testID, testVersion)
		require.NoError(t, err)
		require.Equal(t, testShare, string(v1Data))

		v2Data, err := mock.GetSocialShare(ctx, testID, updatedVersion)
		require.NoError(t, err)
		require.Equal(t, updatedShare, string(v2Data))
	})
}
