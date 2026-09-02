// Package control implements the control plane between the hub and agents.
//
// Agents dial the hub's control listener and open a yamux session. The agent
// opens a single registration stream presenting its token. Once registered,
// the hub opens additional yamux streams that the agent uses to execute sessions
// or receive automatic binary updates.
package control

import (
	"encoding/json"
	"fmt"
	"io"
)

// RegisterRequest is sent by an agent over its registration stream.
type RegisterRequest struct {
	Backend string `json:"backend,omitempty"`
	Token   string `json:"token"`
	Version string `json:"version,omitempty"`
	OS      string `json:"os,omitempty"`
	Arch    string `json:"arch,omitempty"`
	// HostKey is the agent's SSH host public key in authorized_keys form. The
	// hub pins it so a later session cannot be served by a different endpoint.
	HostKey string `json:"host_key,omitempty"`
}

// RegisterResponse is the hub's reply to a RegisterRequest.
type RegisterResponse struct {
	OK              bool   `json:"ok"`
	Backend         string `json:"backend,omitempty"`
	Error           string `json:"error,omitempty"`
	UpdateAvailable bool   `json:"update_available,omitempty"`
	LatestVersion   string `json:"latest_version,omitempty"`
}

// UpdateHeader describes an update payload sent over an update stream.
type UpdateHeader struct {
	Version   string `json:"version"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature,omitempty"` // Ed25519 signature of the SHA256 hex string
}

// WriteRegister encodes a RegisterRequest onto the stream.
func WriteRegister(w io.Writer, req RegisterRequest) error {
	enc := json.NewEncoder(w)
	return enc.Encode(req)
}

// ReadRegister decodes a RegisterRequest from the stream.
func ReadRegister(r io.Reader) (RegisterRequest, error) {
	var req RegisterRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return req, err
	}
	return req, nil
}

// WriteResponse encodes a RegisterResponse onto the stream.
func WriteResponse(w io.Writer, resp RegisterResponse) error {
	return json.NewEncoder(w).Encode(resp)
}

// ReadResponse decodes a RegisterResponse from the stream.
func ReadResponse(r io.Reader) (RegisterResponse, error) {
	var resp RegisterResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// WriteUpdateHeader encodes an UpdateHeader onto the stream.
func WriteUpdateHeader(w io.Writer, header UpdateHeader) error {
	return json.NewEncoder(w).Encode(header)
}

// ReadUpdateHeader decodes an UpdateHeader from the stream.
func ReadUpdateHeader(r io.Reader) (UpdateHeader, error) {
	var header UpdateHeader
	if err := json.NewDecoder(r).Decode(&header); err != nil {
		return header, err
	}
	return header, nil
}

// RegistrationError reports a registration failure with its message.
type RegistrationError struct {
	Message string
}

func (e *RegistrationError) Error() string {
	return fmt.Sprintf("registration failed: %s", e.Message)
}
