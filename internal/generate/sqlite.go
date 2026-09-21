/*
Copyright 2026 The Kubernetes Authors.

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

package generate

import (
	// unpack reads the RPM databases of recent distributions
	// (rpmdb.sqlite) through go-rpmdb, which opens them with the
	// database/sql driver named "sqlite" but registers none. Without a
	// driver, images based on those distributions come out without their
	// OS packages. The legacy pkg/osinfo scanner also imports it, but
	// generation no longer goes through that package.
	//
	// database/sql panics when two drivers register the same name. The
	// modernc.org/sqlite driver package registers "sqlite" as well:
	// should it ever be linked in (today only its library is, through
	// this driver), one of the two imports has to go.
	_ "github.com/glebarez/go-sqlite"
)
