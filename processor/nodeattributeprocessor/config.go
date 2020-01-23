// Copyright 2019 OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nodeattributesprocessor

import "github.com/open-telemetry/opentelemetry-collector/config/configmodels"

// KeyValue specifies a key and value.
type KeyValue struct {
	// Key is the name of the attribute to add
	Key string `mapstructure:"key"`

	// Value is the value of the attribute to add - this is always a string for node attributes
	Value string `mapstructure:"value"`
}

// Config provides set the of key/value pairs that are to be added to the node attributes.
type Config struct {
	configmodels.ProcessorSettings `mapstructure:",squash"`

	// Attributes specifies the value to add
	Attributes []KeyValue `mapstructure:"attributes"`
}
