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

	"github.com/open-telemetry/opentelemetry-collector/component"
	"github.com/open-telemetry/opentelemetry-collector/consumer"
	"github.com/open-telemetry/opentelemetry-collector/consumer/consumerdata"
	"github.com/open-telemetry/opentelemetry-collector/oterr"
	"github.com/open-telemetry/opentelemetry-collector/processor"
)

type processorConfig struct {
	Attributes map[string]string
}

type attributesProcessor struct {
	nextConsumer consumer.TraceConsumer
	config       processorConfig
}

// Start prepares the processor for receiving data.
func (a *attributesProcessor) Start(host component.Host) error {
	return nil
}

// Shutdown allows the processor to clean up before exit.
func (a *attributesProcessor) Shutdown() error {
	return nil
}

// GetCapabilities allows the processor to specify how it processes data.
func (a *attributesProcessor) GetCapabilities() processor.Capabilities {
	return processor.Capabilities{MutatesConsumedData: true}
}

// ConsumeTraceData receives trace data and adds the node attributes specified.
func (a *attributesProcessor) ConsumeTraceData(ctx context.Context, td consumerdata.TraceData) error {
	if td.Node.Attributes == nil {
		td.Node.Attributes = a.config.Attributes
	} else {
		for k, v := range a.config.Attributes {
			td.Node.Attributes[k] = v
		}
	}
	return a.nextConsumer.ConsumeTraceData(ctx, td)
}

func newTraceProcessor(nextConsumer consumer.TraceConsumer, config processorConfig) (processor.TraceProcessor, error) {
	if nextConsumer == nil {
		return nil, oterr.ErrNilNextConsumer
	}

	ap := &attributesProcessor{
		nextConsumer: nextConsumer,
		config:       config,
	}

	return ap, nil
}
