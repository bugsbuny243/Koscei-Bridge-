package services

import (
	"strings"
	"testing"
)

func TestPumpSolanaCaseVariantFixtureActuallyCollidesWhenFolded(t *testing.T) {
	mintA := "AbCDefGHjkMNpQRstUVwxYZ123456789"
	mintB := "aBcdefghJKmnPqrSTuvWXyz123456789"
	if mintA == mintB {
		t.Fatal("fixtures must be exact-case distinct")
	}
	if !strings.EqualFold(mintA, mintB) {
		t.Fatal("fixtures must collide under case folding to exercise the regression")
	}
}
