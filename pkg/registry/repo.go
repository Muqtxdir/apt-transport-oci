package registry

import (
	"context"
	"path"
	"sync"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"
)

const mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"

// blobs is the read-only part of oras-go's registry.BlobStore.
type blobs interface {
	content.Fetcher
	registry.ReferenceFetcher
}

// Repo is a resolved ref and its blobs, which the caller verifies.
type Repo struct {
	blobs
	target content.ReadOnlyStorage
	root   ocispec.Descriptor

	mu    sync.Mutex
	files map[string]ocispec.Descriptor
}

// Algorithm is the digest algorithm of the ref, which its blobs are stored under.
func (r *Repo) Algorithm() digest.Algorithm {
	return r.root.Digest.Algorithm()
}

// Lookup returns the layer titled title. The titles are mapped on first use
// from the resolved root, and a failed mapping is retried.
func (r *Repo) Lookup(ctx context.Context, title string) (ocispec.Descriptor, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.files == nil {
		files, err := buildFileMap(ctx, r.target, r.root)
		if err != nil {
			return ocispec.Descriptor{}, false, err
		}
		r.files = files
	}
	layer, ok := r.files[title]
	return layer, ok, nil
}

// buildFileMap maps the title of each layer under root to its descriptor.
// oras.CopyGraph fetches only the manifests, verified and capped at
// MaxMetadataBytes.
func buildFileMap(ctx context.Context, storage content.ReadOnlyStorage, root ocispec.Descriptor) (map[string]ocispec.Descriptor, error) {
	files := make(map[string]ocispec.Descriptor)
	var filesMu sync.Mutex
	copyOptions := oras.DefaultCopyGraphOptions
	copyOptions.FindSuccessors = func(ctx context.Context, fetcher content.Fetcher, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		successors, err := content.Successors(ctx, fetcher, node)
		if err != nil {
			return nil, err
		}
		switch node.MediaType {
		case ocispec.MediaTypeImageIndex, mediaTypeDockerManifestList:
			return successors, nil
		}
		filesMu.Lock()
		defer filesMu.Unlock()
		for _, layer := range successors {
			if title := layer.Annotations[ocispec.AnnotationTitle]; title != "" {
				files[path.Clean(title)] = layer
			}
		}
		return nil, nil
	}
	if err := oras.CopyGraph(ctx, storage, memory.New(), root, copyOptions); err != nil {
		return nil, err
	}
	return files, nil
}
