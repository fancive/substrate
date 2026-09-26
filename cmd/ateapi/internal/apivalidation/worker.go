// Copyright 2026 Google LLC
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

package apivalidation

import (
	"context"

	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"k8s.io/apimachinery/pkg/api/operation"
	"k8s.io/apimachinery/pkg/api/validate"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// This is needed because DV doesn't have a standard format for IP addresses yet.
func ValidateCustom_Worker_Ip(_ context.Context, _ operation.Operation, fldPath *field.Path, value, _ *string) field.ErrorList {
	return validation.IsValidIP(fldPath, *value)
}

// This exists only because nested subfield tags are not supported yet.
func ValidateCustom_UpdateWorkerRequest_Worker(ctx context.Context, op operation.Operation, fldPath *field.Path, worker, _ *ateapipb.Worker) field.ErrorList {
	if worker == nil || worker.Metadata == nil {
		return nil // handled by DV
	}

	// Updates are validated in 2 steps: first the update request and then the
	// resource itself. DV for the request doesn't descend into the resource
	// metadata.  Once DV supports nested subfield tags, this can be changed to
	// something like:
	//   +k8s:subfield(metadata)=+k8s:subfield(atespace)=+k8s:forbidden
	// Workers are global-scoped, so metadata.atespace must be empty.
	errs := Validate_ResourceMetadata(ctx, op, fldPath.Child("metadata"), worker.Metadata, nil)
	errs = append(errs, validate.ForbiddenValue(ctx, op, fldPath.Child("metadata", "atespace"), &worker.Metadata.Atespace, nil)...)
	return errs
}
