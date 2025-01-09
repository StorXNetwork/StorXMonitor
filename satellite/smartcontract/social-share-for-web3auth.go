package smartcontract

import "context"

var _ SocialShareHelper = (*web3AuthSocialShareHelper)(nil)

type SocialShareHelper interface {
	UploadSocialShare(ctx context.Context, id string, share []byte) error
	GetSocialShare(ctx context.Context, id string) ([]byte, error)
}

var socialShareData = make(map[string][]byte)

type web3AuthSocialShareHelper struct {
}

func NewWeb3AuthSocialShareHelper(web3Config *Web3Config) *web3AuthSocialShareHelper {
	return &web3AuthSocialShareHelper{}
}

func (w *web3AuthSocialShareHelper) UploadSocialShare(ctx context.Context, id string, share []byte) error {
	socialShareData[id] = share
	return nil
}

func (w *web3AuthSocialShareHelper) GetSocialShare(ctx context.Context, id string) ([]byte, error) {
	return socialShareData[id], nil
}
