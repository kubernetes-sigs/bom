package github

import (
	"context"

	gogit "github.com/google/go-github/v60/github"

	"k8s.io/utils/ptr"

	"sigs.k8s.io/release-sdk/github"
)

func UploadSBOMAsset(ctx context.Context, owner, repo, tag, sbomFile string) error {
	client := github.New()

	release, res, err := client.Client().GetReleaseByTag(ctx, owner, repo, tag)
	if err != nil && res.StatusCode != 404 {
		return err
	}

	// maybe the release is in draft mode
	if release == nil {
		releases, err := client.Releases(owner, repo, true)
		if err != nil && res.StatusCode != 404 {
			return err
		}

		for _, r := range releases {
			if tag == r.GetTagName() {
				release = r
				break
			}
		}
	}

	// if we still can't find the release, create a new one
	if release == nil {
		opts := &gogit.RepositoryRelease{
			TagName:    ptr.To(tag),
			Name:       ptr.To(tag),
			Draft:      ptr.To(true),
			Prerelease: ptr.To(false),
		}
		release, err = client.Client().UpdateReleasePage(ctx, owner, repo, 0, opts)
		if err != nil {
			return err
		}
	}

	_, err = client.UploadReleaseAsset(owner, repo, release.GetID(), sbomFile)
	if err != nil {
		return err
	}

	return nil
}
