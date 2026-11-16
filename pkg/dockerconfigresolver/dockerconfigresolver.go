/*
   Copyright The containerd Authors.

   Original source: https://github.com/containerd/nerdctl/blob/v0.9.0/pkg/imgutil/dockerconfigresolver/dockerconfigresolver.go
   We copy the source from upstream nerdctl v0.9.0 for easier packageing
   on debian system. We can delete this file and add upstream nerdctl
   back when:
   1, nerdctl is packaged in debian
   2, apt-transport-oci can use the packaged nerdctl in debian

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package dockerconfigresolver

import (
	dockercliconfig "github.com/docker/cli/cli/config"
	"github.com/sirupsen/logrus"
)

// Credentials is for config.HostOptions of containerd. It returns the
// credentials for host using $DOCKER_CONFIG/config.json and its credential
// helpers.
//
// $DOCKER_CONFIG defaults to "~/.docker".
//
// host is like "registry-1.docker.io".
func Credentials(host string) (string, string, error) {
	// containerd asks for "registry-1.docker.io" when the ref is "docker.io",
	// but "docker.io" appears as "https://index.docker.io/v1/" in ~/.docker/config.json .
	// GetAuthConfig takes the hostname part as the argument: "index.docker.io"
	if host == "registry-1.docker.io" {
		host = "index.docker.io"
	}
	// Load does not raise an error on ENOENT
	dockerConfigFile, err := dockercliconfig.Load("")
	if err != nil {
		return "", "", err
	}
	// GetAuthConfig does not raise an error on ENOENT
	ac, err := dockerConfigFile.GetAuthConfig(host)
	if err != nil {
		logrus.WithError(err).Warnf("cannot get auth config for %q", host)
		return "", "", nil
	}
	// RegistryToken is not supported, as in containerd/CRI.
	if ac.IdentityToken != "" {
		return "", ac.IdentityToken, nil
	}
	return ac.Username, ac.Password, nil
}
