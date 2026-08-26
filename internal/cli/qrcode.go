package cli

import "github.com/skip2/go-qrcode"

// renderQRCode returns an ASCII QR code for content, sized for a normal
// terminal window. Uses the lowest error correction level (Low) to keep
// the code as small as possible, that's fine here since this is scanned
// straight off a screen, not read damaged or dirty like a printed code.
// Returns an error if content can't be encoded, callers should fall back
// to showing the secret manually in that case.
func renderQRCode(content string) (string, error) {
	qr, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}
