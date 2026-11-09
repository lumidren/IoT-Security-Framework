// Package attest verifies the IronMesh enrollment attestation (DESIGN_CONTRACT
// §3, WIRE_FORMAT.md §4): a COSE_Sign1 (tag 18, ES256) signed by the device's
// current identity key over a type-10 envelope {1: seq, 2: ts, 3: 10, 4: body}
// whose body is the CBOR map
//
//	{1: nonce, 2: sha256(csr_der), 3: fw_hash, 4: fw_version, 5: se_type, 6: evidence}
//
// where evidence is null for atecc608/optee/software and a TPM2 quote map
// {1: quote (TPMS_ATTEST), 2: signature (TPMT_SIGNATURE), 3: ak_cert_der}
// for se_type "tpm2".
//
// Verification is split into steps so the EST handler can interleave its own
// checks (nonce consumption, registry lookups) and map failures to RFC 7030
// status codes: Parse -> VerifySignature -> VerifyTimestamp -> VerifyKeyID ->
// (nonce) -> VerifyBinding -> VerifyEvidence.
package attest

import (
	"errors"
	"fmt"
)

// Code classifies attestation failures for HTTP mapping.
type Code int

// Failure classes.
const (
	// CodeMalformed means the attestation could not be decoded or violates
	// the schema (HTTP 400).
	CodeMalformed Code = iota + 1
	// CodeUnauthorized means a cryptographic check failed: signature, nonce
	// or quote binding (HTTP 401).
	CodeUnauthorized
	// CodeForbidden means the attestation is valid but policy rejects it:
	// software keys, PCR values, AK chain (HTTP 403).
	CodeForbidden
)

func (c Code) String() string {
	switch c {
	case CodeMalformed:
		return "malformed"
	case CodeUnauthorized:
		return "unauthorized"
	case CodeForbidden:
		return "forbidden"
	}
	return fmt.Sprintf("code(%d)", int(c))
}

// Error is an attestation failure with a classification.
type Error struct {
	Code   Code
	Reason string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attestation %s: %s: %v", e.Code, e.Reason, e.Err)
	}
	return fmt.Sprintf("attestation %s: %s", e.Code, e.Reason)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

func malformed(reason string, err error) *Error {
	return &Error{Code: CodeMalformed, Reason: reason, Err: err}
}
func unauthorized(reason string, err error) *Error {
	return &Error{Code: CodeUnauthorized, Reason: reason, Err: err}
}
func forbidden(reason string, err error) *Error {
	return &Error{Code: CodeForbidden, Reason: reason, Err: err}
}

// CodeOf extracts the Code from err, defaulting to CodeMalformed.
func CodeOf(err error) Code {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return CodeMalformed
}
