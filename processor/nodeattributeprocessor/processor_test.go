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
	"context"
	"testing"

	commonpb "github.com/census-instrumentation/opencensus-proto/gen-go/agent/common/v1"
	"github.com/stretchr/testify/assert"

	"github.com/open-telemetry/opentelemetry-collector/component"
	"github.com/open-telemetry/opentelemetry-collector/consumer/consumerdata"
	"github.com/open-telemetry/opentelemetry-collector/exporter/exportertest"
	"github.com/open-telemetry/opentelemetry-collector/processor"
)

func TestStart(t *testing.T) {
	p := attributesProcessor{}
	err := p.Start(component.NewMockHost())
	assert.NoError(t, err)
}

func TestStop(t *testing.T) {
	p := attributesProcessor{}
	err := p.Shutdown()
	assert.NoError(t, err)
}

func TestGetCapabilities(t *testing.T) {
	p := attributesProcessor{}
	caps := p.GetCapabilities()
	assert.Equal(t, processor.Capabilities{MutatesConsumedData: true}, caps)
}

func TestConsumeTraceData(t *testing.T) {
	p := attributesProcessor{
		nextConsumer: exportertest.NewNopTraceExporter(),
		config:       processorConfig{Attributes: map[string]string{"test key": "test value"}},
	}

	td0 := consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: nil,
		},
	}
	err := p.ConsumeTraceData(context.Background(), td0)
	assert.NoError(t, err)
	assert.Equal(t, consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: map[string]string{"test key": "test value"},
		},
	}, td0)

	td1 := consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: map[string]string{"some key": "some value"},
		},
	}
	err = p.ConsumeTraceData(context.Background(), td1)
	assert.NoError(t, err)
	assert.Equal(t, consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: map[string]string{
				"some key": "some value",
				"test key": "test value",
			},
		},
	}, td1)

	td2 := consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: map[string]string{"test key": "old value"},
		},
	}
	err = p.ConsumeTraceData(context.Background(), td2)
	assert.NoError(t, err)
	assert.Equal(t, consumerdata.TraceData{
		Node: &commonpb.Node{
			Attributes: map[string]string{"test key": "test value"},
		},
	}, td2)
}
