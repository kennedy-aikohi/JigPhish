package parser

import (
	"bytes"
	"encoding/base64"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"regexp"
	"strings"

	"github.com/kennedy-aikohi/jigphish/internal/model"
	"github.com/kennedy-aikohi/jigphish/pkg/defang"
	"github.com/makiuchi-d/gozxing"
	mqrcode "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"
)

var inlineBase64ImageRE = regexp.MustCompile(`data:image/[^;]{1,20};base64,([A-Za-z0-9+/\s]+=*)`)

// detectBarcodesFromBytes decodes QR codes (and multi-QR images) from raw image
// bytes. Returns nil when the data is not a recognisable image or no codes are
// found. A recover() wrapper guards against panics in the ZXing decoder.
func detectBarcodesFromBytes(data []byte) (arts []model.BarcodeArtifact) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return decodeBarcodesFromImage(img)
}

func decodeBarcodesFromImage(img image.Image) (arts []model.BarcodeArtifact) {
	defer func() { recover() }() // ZXing can panic on malformed images

	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil
	}

	// Try the multi-QR reader first — finds all QR codes in a single image.
	multiReader := mqrcode.NewQRCodeMultiReader()
	results, _ := multiReader.DecodeMultiple(bmp, nil)

	// Fall back to single QR decode when the multi-reader found nothing.
	if len(results) == 0 {
		single, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
		if err == nil && single != nil {
			results = []*gozxing.Result{single}
		}
	}

	for _, r := range results {
		arts = append(arts, barcodeArtifactFromResult(r))
	}
	return arts
}

func barcodeArtifactFromResult(r *gozxing.Result) model.BarcodeArtifact {
	data := r.GetText()
	art := model.BarcodeArtifact{
		Format: r.GetBarcodeFormat().String(),
		Data:   data,
	}
	u, err := url.Parse(data)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		art.IsURL = true
		art.Domain = strings.ToLower(u.Hostname())
		art.Defanged = defang.URL(data)
	}
	return art
}

// extractInlineImageBarcodes scans the email body (which may contain raw HTML)
// for base64-encoded inline images (data: URIs) and runs QR detection on each.
// Capped at 20 inline images per email to prevent excessive CPU use.
func extractInlineImageBarcodes(htmlBody string) []model.BarcodeArtifact {
	var arts []model.BarcodeArtifact
	matches := inlineBase64ImageRE.FindAllStringSubmatch(htmlBody, 20)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		b64 := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(strings.TrimSpace(m[1]))
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				continue
			}
		}
		arts = append(arts, detectBarcodesFromBytes(data)...)
	}
	return arts
}
