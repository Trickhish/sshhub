package control

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// Stream session-authorization protocol (hub -> agent).
//
// WHY THIS EXISTS
//
// Previously the hub asserted the client's identity by sending the client's
// public key as an SSH *password*, which the agent compared against
// authorized_keys. A public key is not a secret -- it is published in
// authorized_keys files, on forges, and via ssh-keyscan -- so anyone able to
// speak SSH to the agent could present a victim's public key and be accepted.
// The key was effectively a bearer token.
//
// The authorization now travels in a framed header at the head of the yamux
// stream instead. That stream only exists inside the control session the agent
// itself dialled out and authenticated with its registration token, so a frame
// arriving on it provably came from the hub. The client's public key is no
// longer a credential: it is an identifier inside an already-authenticated
// channel.
//
// FRAMING
//
// Explicitly length-prefixed, and read with io.ReadFull, because the stream is
// handed to the SSH layer immediately afterwards. A buffering reader (such as
// json.Decoder) could consume bytes belonging to the SSH handshake.
//
//	"SSHH" | version(1) | length(4, big endian) | JSON payload

const (
	streamMagic            = "SSHH"
	streamVersion     byte = 1
	maxStreamFrame         = 64 * 1024
	streamAuthTimeout      = 15 * time.Second
)

// Session purposes.
const (
	// PurposeVerify only asks the agent to authorize the key. The agent replies
	// and closes; no SSH handshake follows. Used during the hub's own SSH
	// handshake so an unauthorized key is refused at the right protocol layer.
	PurposeVerify = "verify"
	// PurposeSession authorizes and then carries an SSH connection.
	PurposeSession = "session"
)

// SessionRequest is the hub's authorization assertion for one stream.
type SessionRequest struct {
	Purpose string `json:"purpose"`
	// EndUser is the Unix account the session must run as, taken from the
	// matched route's end_user. The agent independently verifies the account
	// exists and that ClientKey is authorized for it.
	EndUser string `json:"end_user"`
	// ClientKey is the connecting client's public key in authorized_keys form.
	ClientKey string `json:"client_key"`
}

// SessionResponse is the agent's verdict.
type SessionResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}
	if len(payload) > maxStreamFrame {
		return fmt.Errorf("frame too large (%d bytes)", len(payload))
	}

	buf := make([]byte, 0, len(streamMagic)+1+4+len(payload))
	buf = append(buf, streamMagic...)
	buf = append(buf, streamVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// readFrame reads exactly one frame, consuming no more bytes than it contains.
func readFrame(r io.Reader, v any) error {
	head := make([]byte, len(streamMagic)+1+4)
	if _, err := io.ReadFull(r, head); err != nil {
		return fmt.Errorf("read frame header: %w", err)
	}
	if string(head[:len(streamMagic)]) != streamMagic {
		return fmt.Errorf("bad frame magic (peer is not an sshhub endpoint)")
	}
	if got := head[len(streamMagic)]; got != streamVersion {
		return fmt.Errorf("unsupported stream protocol version %d (this build speaks %d); "+
			"hub and agent must be upgraded together", got, streamVersion)
	}

	n := binary.BigEndian.Uint32(head[len(streamMagic)+1:])
	if n > maxStreamFrame {
		return fmt.Errorf("frame too large (%d bytes)", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return fmt.Errorf("read frame payload: %w", err)
	}
	return json.Unmarshal(payload, v)
}

// RequestSession performs the hub side of the exchange: send the assertion and
// wait for the agent's verdict. A non-nil error means the session is NOT
// authorized and the stream must be discarded.
func RequestSession(conn net.Conn, req SessionRequest) error {
	_ = conn.SetDeadline(time.Now().Add(streamAuthTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if err := writeFrame(conn, req); err != nil {
		return err
	}
	var resp SessionResponse
	if err := readFrame(conn, &resp); err != nil {
		return err
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unauthorized"
		}
		return fmt.Errorf("agent refused session: %s", resp.Error)
	}
	return nil
}

// AcceptSession performs the agent side: read the hub's assertion. The caller
// must validate it and reply with ReplySession before doing anything else.
func AcceptSession(conn net.Conn) (SessionRequest, error) {
	_ = conn.SetDeadline(time.Now().Add(streamAuthTimeout))
	var req SessionRequest
	if err := readFrame(conn, &req); err != nil {
		return req, err
	}
	if req.Purpose != PurposeVerify && req.Purpose != PurposeSession {
		return req, fmt.Errorf("unknown purpose %q", req.Purpose)
	}
	return req, nil
}

// ReplySession sends the agent's verdict and clears the handshake deadline so
// the (potentially long-lived) session that follows is not cut off.
func ReplySession(conn net.Conn, ok bool, reason string) error {
	resp := SessionResponse{OK: ok}
	if !ok {
		// Deliberately coarse: the hub is trusted, but there is no reason to
		// describe which of account-missing / key-not-authorized failed.
		resp.Error = reason
	}
	err := writeFrame(conn, resp)
	_ = conn.SetDeadline(time.Time{})
	return err
}
