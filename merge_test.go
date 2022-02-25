package cyclonedx

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestMergeFlat(t *testing.T) {
	t.Run("Components", func(t *testing.T) {
		t.Run("WithoutSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-flat.json")
			)

			result, err := MergeFlat(nil, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})

		t.Run("WithSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				subject        = readTestBOM(t, "./testdata/merge/components-subject.json").Metadata.Component
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-flat-subject.json")
			)

			result, err := MergeFlat(subject, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})
	})
}

func TestMergeLink(t *testing.T) {
	t.Run("Components", func(t *testing.T) {
		t.Run("WithoutSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-link.json")
			)

			result, err := MergeLink(nil, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})

		t.Run("WithSubject", func(t *testing.T) {
			var (
				bomA           = readTestBOM(t, "./testdata/merge/components-bom-a.json")
				bomB           = readTestBOM(t, "./testdata/merge/components-bom-b.json")
				subject        = readTestBOM(t, "./testdata/merge/components-subject.json").Metadata.Component
				resultExpected = readTestBOM(t, "./testdata/merge/components-result-link-subject.json")
			)

			result, err := MergeLink(subject, bomA, bomB)
			require.NoError(t, err)

			if !cmp.Equal(result, resultExpected, filterXMLNS) {
				require.FailNow(t, "unexpected merge result", cmp.Diff(result, resultExpected, filterXMLNS))
			}
		})
	})
}

var filterXMLNS = cmp.FilterPath(func(path cmp.Path) bool {
	return path.String() == "XMLNS"
}, cmp.Ignore())
