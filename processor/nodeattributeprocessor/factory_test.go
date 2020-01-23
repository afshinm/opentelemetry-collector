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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector/config/configerror"
	"github.com/open-telemetry/opentelemetry-collector/config/configmodels"
	"github.com/open-telemetry/opentelemetry-collector/exporter/exportertest"
)

func TestType(t *testing.T) {
	factory := Factory{}
	assert.Equal(t, typeStr, factory.Type())
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := Factory{}
	assert.Equal(t, &Config{
		ProcessorSettings: configmodels.ProcessorSettings{
			TypeVal: typeStr,
			NameVal: typeStr,
		},
	}, factory.CreateDefaultConfig())
}

func TestCreateTraceProcessor(t *testing.T) {
	factory := Factory{}
	cfg := factory.CreateDefaultConfig()
	p, err := factory.CreateTraceProcessor(zap.NewNop(), exportertest.NewNopTraceExporter(), cfg)
	assert.NoError(t, err)
	assert.NotNil(t, p)

	cfg.(*Config).Attributes = []KeyValue{
		{Key: "some_key", Value: "some_value"},
		{Key: "some_other_key", Value: "42"},
	}

	p, err = factory.CreateTraceProcessor(zap.NewNop(), exportertest.NewNopTraceExporter(), cfg)
	assert.NoError(t, err)
	assert.NotNil(t, p)
}

func TestCreateMetricsProcessor(t *testing.T) {
	factory := Factory{}
	cfg := factory.CreateDefaultConfig()
	p, err := factory.CreateMetricsProcessor(zap.NewNop(), exportertest.NewNopMetricsExporter(), cfg)
	assert.Equal(t, configerror.ErrDataTypeIsNotSupported, err)
	assert.Nil(t, p)
}
