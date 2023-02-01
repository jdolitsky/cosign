//
// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v2/pkg/oci"
	ctypes "github.com/sigstore/cosign/v2/pkg/types"
)

// ArtifactType converts a attachment name (sig/sbom/att/etc.) into a valid artifactType (OCI 1.1+).
func ArtifactType(attName string) string {
	return fmt.Sprintf("application/vnd.dev.cosign.artifact.%s.v1+json", attName)
}

// Referrers fetches references using registry options.
func Referrers(d name.Digest, artifactType string, rOpts ...remote.Option) (*v1.IndexManifest, error) {
	if rOpts == nil {
		rOpts = []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		}
	}
	rOpts = append(rOpts, remote.WithFilter("artifactType", artifactType))
	return remote.Referrers(d, rOpts...)
}

// WriteSignaturesExperimentalOCI publishes the signatures attached to the given entity
// into the provided repository (using OCI 1.1 methods).
func WriteSignaturesExperimentalOCI(d name.Digest, se oci.SignedEntity, opts ...remote.Option) error {
	// TODO
	//o := makeOptions(d.Repository, opts...)
	signTarget := d.String()
	ref, err := name.ParseReference(signTarget) // TODO, o.NameOpts...)
	if err != nil {
		return err
	}
	desc, err := remote.Head(ref) // TODO, o.ROpt...)
	if err != nil {
		return err
	}
	sigs, err := se.Signatures()
	if err != nil {
		return err
	}

	// Write the signature blobs
	s, err := sigs.Get()
	if err != nil {
		return err
	}
	for _, v := range s {
		if err := remote.WriteLayer(d.Repository, v); err != nil { // TODO, o.ROpt...); err != nil {
			return err
		}
	}

	// Write the manifest containing a subject
	b, err := sigs.RawManifest()
	if err != nil {
		return err
	}
	var m v1.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	artifactType := ArtifactType("sig")
	m.Config.MediaType = types.MediaType(artifactType)
	m.Subject = desc
	b, err = json.Marshal(&m)
	if err != nil {
		return err
	}
	digest, _, err := v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return err
	}
	targetRef, err := name.ParseReference(fmt.Sprintf("%s/%s@%s", d.RegistryStr(), d.RepositoryStr(), digest.String()))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Uploading signature for [%s] to [%s] with config.mediaType [%s] layers[0].mediaType [%s].\n",
		d.String(), targetRef.String(), artifactType, ctypes.SimpleSigningMediaType)
	return remote.Put(targetRef, &taggableManifest{raw: b, mediaType: m.MediaType}) // TODO, o.ROpt...)
}

type taggableManifest struct {
	raw       []byte
	mediaType types.MediaType
}

func (taggable taggableManifest) RawManifest() ([]byte, error) {
	return taggable.raw, nil
}

func (taggable taggableManifest) MediaType() (types.MediaType, error) {
	return taggable.mediaType, nil
}
