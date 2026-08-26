package cli

import "github.com/skip2/go-qrcode"

// renderQRCode returns an ASCII QR code for content, sized for a normal
// terminal window. Uses the lowest error correction level (Low) to keep
// the code as small as possible.
func renderQRCode(content string) (string, error) {
	qr, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return "", err
	}
	return qr.ToSmallString(false), nil
}
