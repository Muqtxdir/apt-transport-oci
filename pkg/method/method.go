package method

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/AkihiroSuda/apt-transport-oci/pkg/apt"
	"github.com/AkihiroSuda/apt-transport-oci/pkg/dockerconfigresolver"
	"github.com/AkihiroSuda/apt-transport-oci/pkg/version"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
	refdocker "github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Protocol: see https://justi.cz/security/2019/01/22/apt-rce.html
// See also the output of `apt-get -o Debug::pkgAcquire::Worker=1 update`
const (
	FieldURI              = "URI"
	FieldMessage          = "Message"
	FieldTargetRepoURI    = "Target-Repo-URI"
	FieldFilename         = "Filename"
	FieldSize             = "Size"
	FieldSHA256Hash       = "SHA256-Hash"
	FieldExpectedSHA256   = "Expected-SHA256"
	FieldSHA512Hash       = "SHA512-Hash"
	FieldExpectedSHA512   = "Expected-SHA512"
	FieldExpectedFileSize = "Expected-Checksum-FileSize"
	FieldFailReason       = "FailReason"
)

const (
	MediaTypeApplicationXBinary     = "application/x-binary"
	MediaTypeApplicationOctetStream = "application/octet-stream"
)

func New(out io.Writer, in io.Reader) *Method {
	m := &Method{
		w:             apt.NewMessageWriter(out),
		r:             apt.NewMessageReader(in),
		cacheByOCIRef: make(map[string]cacheByOCIRef),
	}
	return m
}

type cacheByOCIRef struct {
	fetcher remotes.Fetcher
	fileMap map[string]ocispec.Descriptor
}

type Method struct {
	w *apt.MessageWriter
	r *apt.MessageReader

	// each ref is resolved only once at a time
	cacheMu sync.Mutex
	// no need to consider cache invalidation, as the process lifecycle is short
	cacheByOCIRef map[string]cacheByOCIRef
}

// Run is based on https://github.com/cloudflare/apt-transport-cloudflared/blob/96e1417f9c54/apt/method.go#L77-L108
func (m *Method) Run(ctx context.Context) {
	version := fmt.Sprintf("%d.%d", version.Major, version.Minor)
	m.w.WriteMessage(apt.CodeCapabilities,
		apt.Field{Key: "Version", Value: version},
		apt.Field{Key: "Pipeline", Value: "true"},
	)
	var requests sync.WaitGroup
	defer requests.Wait()
	for {
		msg, err := m.r.ReadMessage()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return
		}
		if err != nil {
			m.w.WriteMessage(apt.CodeGeneralFailure,
				apt.Field{Key: FieldMessage, Value: fmt.Sprintf("Error reading message: %v", err)})
			return
		}
		switch msg.StatusCode {
		case apt.CodeURIAcquire:
			requests.Go(func() { m.handleURIAcquire(ctx, msg) })
		default:
			m.w.WriteMessage(apt.CodeLog,
				apt.Field{Key: FieldMessage, Value: fmt.Sprintf("Unknown message: %d %s", msg.StatusCode, msg.Description)})
		}
	}
}

func (m *Method) handleURIAcquire(ctx context.Context, msg *apt.Message) {
	if started, err := m.acquire(ctx, msg); err != nil {
		uri := msg.Fields.Get(FieldURI)
		if !started {
			m.w.WriteMessage(apt.CodeURIStart, apt.Field{Key: FieldURI, Value: uri})
		}
		m.w.WriteMessage(apt.CodeURIFailure,
			apt.Field{Key: FieldURI, Value: uri},
			apt.Field{Key: FieldFailReason, Value: err.Error()},
		)
	}
}

func (m *Method) ociResolver() remotes.Resolver {
	// TODO: support insecure non-TLS registry
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: config.ConfigureHosts(context.Background(), config.HostOptions{
			Credentials: dockerconfigresolver.Credentials,
		}),
	})
}

func (m *Method) ociFetcher(ctx context.Context, named refdocker.Named, resolver remotes.Resolver) (remotes.Fetcher, ocispec.Descriptor, error) {
	ref := named.String()
	ociName, rootDesc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, ocispec.Descriptor{}, fmt.Errorf("failed to resolve ref=%q: %w", ref, err)
	}
	fetcher, err := resolver.Fetcher(ctx, ociName)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}

	return fetcher, rootDesc, nil
}

func buildFileMap(ctx context.Context, fetcher remotes.Fetcher, rootDesc ocispec.Descriptor) (map[string]ocispec.Descriptor, error) {
	files := make(map[string]ocispec.Descriptor)
	var filesMu sync.Mutex
	handler := images.HandlerFunc(
		func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			switch desc.MediaType {
			case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
				r, err := fetcher.Fetch(ctx, desc)
				if err != nil {
					return nil, err
				}
				defer r.Close()
				b, err := io.ReadAll(r)
				if err != nil {
					return nil, err
				}
				var manifest ocispec.Manifest
				if err := json.Unmarshal(b, &manifest); err != nil {
					return nil, err
				}
				filesMu.Lock()
				for _, l := range manifest.Layers {
					if title := l.Annotations[ocispec.AnnotationTitle]; title != "" {
						cleanPath := path.Clean(title)
						files[cleanPath] = l
					}
				}
				filesMu.Unlock()
			case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
				r, err := fetcher.Fetch(ctx, desc)
				if err != nil {
					return nil, err
				}
				defer r.Close()
				b, err := io.ReadAll(r)
				if err != nil {
					return nil, err
				}
				var index ocispec.Index
				if err := json.Unmarshal(b, &index); err != nil {
					return nil, err
				}
				return index.Manifests, nil
			}
			return nil, nil
		})
	if err := images.Dispatch(ctx, handler, nil, rootDesc); err != nil {
		return nil, err
	}
	return files, nil
}

func parseURI(uri string) (repo, path string, _ error) {
	// The format here would be something like: registry.somehost.com/some/repo:tag/SomeFile

	trimmed := strings.TrimPrefix(uri, "oci://")
	if trimmed == uri {
		return "", "", fmt.Errorf("missing oci:// protocol in uri")
	}

	split := strings.SplitN(trimmed, ":", 2)
	if len(split) < 2 {
		return "", "", fmt.Errorf("uri is missing repo tag")
	}

	// Combine everything up to but not including the tag
	// We don't quite have the tag yet because it (should) have a file path added
	// to the end that we need to split off first.
	repo = "oci://" + split[0] + ":"
	tagAndFile := strings.SplitN(split[1], "/", 2)

	// We add "/" here, otherwise we'll end up with an extra preceding "/" on the
	// file name later which we don't want and will cause the file to not be found.
	repo += tagAndFile[0] + "/"

	if len(tagAndFile) > 1 {
		path = tagAndFile[1]
	}

	return repo, path, nil
}

func parseURIFields(msg *apt.Message) (ociRef refdocker.Named, title string, err error) {
	repoURI := msg.Fields.Get(FieldTargetRepoURI)
	if repoURI == "" {
		uri := msg.Fields.Get(FieldURI)
		if uri == "" {
			return ociRef, "", fmt.Errorf("missing field %q", FieldTargetRepoURI)
		}
		repoURI, _, err = parseURI(uri)
		if err != nil {
			return ociRef, "", err
		}
	}
	if !strings.HasPrefix(repoURI, "oci://") {
		return ociRef, "", fmt.Errorf("field %s lacks \"oci://\" prefix: %q", FieldTargetRepoURI, repoURI)
	}
	refTmp := strings.TrimPrefix(repoURI, "oci://")
	refTmp = strings.TrimSuffix(refTmp, "/")
	ociRef, err = refdocker.ParseDockerRef(refTmp)
	if err != nil {
		return ociRef, "", fmt.Errorf("failed to parse %q (%s=%q) as Docker reference: %w", refTmp, FieldTargetRepoURI, repoURI, err)
	}
	title = strings.TrimPrefix(msg.Fields.Get(FieldURI), repoURI)
	// not robust, but no security issue (cuz not referring to the actual filesystem)
	title = strings.TrimPrefix(title, "./")
	return ociRef, title, nil
}

func (m *Method) Status(uri, s string) {
	m.w.WriteMessage(apt.CodeStatus,
		apt.Field{Key: FieldURI, Value: uri},
		apt.Field{Key: FieldMessage, Value: s},
	)
}

func (m *Method) Statusf(uri, fmtspec string, args ...any) {
	m.Status(uri, fmt.Sprintf(fmtspec, args...))
}

func (m *Method) doCacheStuff(ctx context.Context, uri string, ociRef refdocker.Named) (*cacheByOCIRef, error) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	if x, ok := m.cacheByOCIRef[ociRef.String()]; ok {
		return &x, nil
	}

	m.Statusf(uri, "Creating a resolver for ociRef=%q", ociRef)
	resolver := m.ociResolver()

	m.Statusf(uri, "Creating a fetcher for ociRef=%q", ociRef)
	fetcher, rootDesc, err := m.ociFetcher(ctx, ociRef, resolver)
	if err != nil {
		return nil, err
	}

	m.Statusf(uri, "Building file map for rootDesc=%+v", rootDesc)
	fileMap, err := buildFileMap(ctx, fetcher, rootDesc)
	if err != nil {
		return nil, err
	}

	c := cacheByOCIRef{
		fetcher: fetcher,
		fileMap: fileMap,
	}
	m.cacheByOCIRef[ociRef.String()] = c
	return &c, nil
}

func expectedBlob(msg *apt.Message) (ocispec.Descriptor, bool) {
	size, err := strconv.ParseInt(msg.Fields.Get(FieldExpectedFileSize), 10, 64)
	if err != nil || size < 0 {
		return ocispec.Descriptor{}, false
	}
	for _, dgst := range []digest.Digest{
		digest.NewDigestFromEncoded(digest.SHA256, msg.Fields.Get(FieldExpectedSHA256)),
		digest.NewDigestFromEncoded(digest.SHA512, msg.Fields.Get(FieldExpectedSHA512)),
	} {
		if dgst.Validate() == nil {
			return ocispec.Descriptor{
				MediaType: MediaTypeApplicationOctetStream,
				Digest:    dgst,
				Size:      size,
			}, true
		}
	}
	return ocispec.Descriptor{}, false
}

func (m *Method) acquire(ctx context.Context, msg *apt.Message) (started bool, err error) {
	uri := msg.Fields.Get(FieldURI)
	filename := msg.Fields.Get(FieldFilename)

	m.Statusf(uri, "Parsing msg: %+v", msg)
	ociRef, title, err := parseURIFields(msg)
	if err != nil {
		return started, err
	}

	c, err := m.doCacheStuff(ctx, uri, ociRef)
	if err != nil {
		return started, err
	}

	desc, ok := c.fileMap[title]
	if !ok {
		desc, ok = expectedBlob(msg)
	}
	if !ok {
		return started, fmt.Errorf("file not found in %q: %q", ociRef, title)
	}
	m.Statusf(uri, "Found descriptor for %q: %+v", title, desc)
	switch desc.MediaType {
	case MediaTypeApplicationOctetStream, MediaTypeApplicationXBinary:
		// NOP
	default:
		m.w.WriteMessage(apt.CodeWarning, apt.Field{Key: FieldMessage,
			Value: fmt.Sprintf("expected media type of %q to be %q, got %q", title, MediaTypeApplicationXBinary, desc.MediaType)})
	}

	m.w.WriteMessage(apt.CodeURIStart,
		apt.Field{Key: FieldURI, Value: uri},
		apt.Field{Key: FieldSize, Value: strconv.FormatInt(desc.Size, 10)},
	)
	started = true

	r, err := c.fetcher.Fetch(ctx, desc)
	if err != nil {
		return started, err
	}
	defer r.Close()

	w, err := os.Create(filename)
	if err != nil {
		return started, err
	}
	defer w.Close()

	sha256Digester, sha512Digester := digest.SHA256.Digester(), digest.SHA512.Digester()
	mw := io.MultiWriter(w, sha256Digester.Hash(), sha512Digester.Hash())

	if _, err := io.Copy(mw, r); err != nil {
		// TODO: show progress
		return started, err
	}

	if err := w.Close(); err != nil {
		return started, err
	}

	if err := r.Close(); err != nil {
		return started, err
	}

	sha256Digest, sha512Digest := sha256Digester.Digest(), sha512Digester.Digest()

	for _, dig := range []digest.Digest{sha256Digest, sha512Digest} {
		if desc.Digest.Algorithm() == dig.Algorithm() && desc.Digest.Encoded() != dig.Encoded() {
			return started, fmt.Errorf("expected digest of %q to be %s, got %s", title, desc.Digest, dig)
		}
	}

	m.w.WriteMessage(apt.CodeURIDone,
		apt.Field{Key: FieldURI, Value: uri},
		apt.Field{Key: FieldFilename, Value: filename},
		apt.Field{Key: FieldSize, Value: strconv.FormatInt(desc.Size, 10)},
		apt.Field{Key: FieldSHA256Hash, Value: sha256Digest.Encoded()},
		apt.Field{Key: FieldSHA512Hash, Value: sha512Digest.Encoded()},
	)
	return started, nil
}
