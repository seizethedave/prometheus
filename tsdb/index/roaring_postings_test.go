// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package index

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/util/testutil"
)

func roaringBitmapToRefs(p *RoaringMemPostings, l labels.Label) []storage.SeriesRef {
	bm := p.m[l.Name][l.Value]
	if bm == nil {
		return nil
	}
	refs := make([]storage.SeriesRef, 0, bm.GetCardinality())
	it := bm.Iterator()
	for it.HasNext() {
		refs = append(refs, storage.SeriesRef(it.Next()))
	}
	return refs
}

func TestRoaringMemPostings_addFor(t *testing.T) {
	p := NewRoaringMemPostings()
	// Pre-populate with {1,2,3,4,6,7,8}.
	for _, ref := range []storage.SeriesRef{1, 2, 3, 4, 6, 7, 8} {
		p.addFor(ref, allPostingsKey)
	}
	// Insert out-of-order ref 5.
	p.addFor(5, allPostingsKey)

	require.Equal(t, []storage.SeriesRef{1, 2, 3, 4, 5, 6, 7, 8}, roaringBitmapToRefs(p, allPostingsKey))
}

func TestRoaringMemPostings_ensureOrder(t *testing.T) {
	p := NewUnorderedRoaringMemPostings()

	for i := range 100 {
		for j := range 100 {
			ref := storage.SeriesRef(rand.Uint32())
			v := strconv.Itoa(i)
			l := labels.Label{Name: "a", Value: v}
			p.addFor(ref, l)
			_ = j
		}
	}

	p.EnsureOrder(0)

	for _, e := range p.m {
		for v, bm := range e {
			it := bm.Iterator()
			var prev uint32
			first := true
			for it.HasNext() {
				cur := it.Next()
				if !first {
					require.True(t, cur > prev, "postings list for %q is not sorted: %d >= %d", v, prev, cur)
				}
				prev = cur
				first = false
			}
		}
	}
}

func TestRoaringMemPostings_Delete(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("lbl1", "a"))
	p.Add(2, labels.FromStrings("lbl1", "b"))
	p.Add(3, labels.FromStrings("lbl2", "a"))

	before := p.Postings(context.Background(), allPostingsKey.Name, allPostingsKey.Value)
	deletedRefs := map[storage.SeriesRef]struct{}{
		2: {},
	}
	affectedLabels := map[labels.Label]struct{}{
		{Name: "lbl1", Value: "b"}: {},
	}
	p.Delete(deletedRefs, affectedLabels)
	after := p.Postings(context.Background(), allPostingsKey.Name, allPostingsKey.Value)

	// Before-delete iterator should see old data because Delete clones the bitmap.
	expanded, err := ExpandPostings(before)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 2, 3}, expanded)

	expanded, err = ExpandPostings(after)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 3}, expanded)

	deleted := p.Postings(context.Background(), "lbl1", "b")
	expanded, err = ExpandPostings(deleted)
	require.NoError(t, err)
	require.Empty(t, expanded, "expected empty postings, got %v", expanded)
}

func TestRoaringMemPostingsStats(t *testing.T) {
	p := NewRoaringMemPostings()

	p.Add(1, labels.FromStrings("label", "value1"))
	p.Add(1, labels.FromStrings("label", "value2"))
	p.Add(1, labels.FromStrings("label", "value3"))
	p.Add(2, labels.FromStrings("label", "value1"))

	stats := p.Stats("label", 10, func(name, value string, n uint64) uint64 { return uint64(len(name)+len(value)) * n })

	require.Equal(t, uint64(2), stats.CardinalityMetricsStats[0].Count)
	require.Equal(t, "value1", stats.CardinalityMetricsStats[0].Name)

	require.Equal(t, uint64(3), stats.CardinalityLabelStats[0].Count)
	require.Equal(t, "label", stats.CardinalityLabelStats[0].Name)

	require.Equal(t, uint64(44), stats.LabelValueStats[0].Count)
	require.Equal(t, "label", stats.LabelValueStats[0].Name)

	require.Equal(t, uint64(2), stats.LabelValuePairsStats[0].Count)
	require.Equal(t, "label=value1", stats.LabelValuePairsStats[0].Name)

	require.Equal(t, 3, stats.NumLabelPairs)
}

func TestRoaringMemPostings_PostingsForLabelMatching(t *testing.T) {
	mp := NewRoaringMemPostings()
	mp.Add(1, labels.FromStrings("foo", "1"))
	mp.Add(2, labels.FromStrings("foo", "2"))
	mp.Add(3, labels.FromStrings("foo", "3"))
	mp.Add(4, labels.FromStrings("foo", "4"))

	isEven := func(v string) bool {
		iv, err := strconv.Atoi(v)
		if err != nil {
			panic(err)
		}
		return iv%2 == 0
	}

	p := mp.PostingsForLabelMatching(context.Background(), "foo", isEven)
	require.NoError(t, p.Err())
	refs, err := ExpandPostings(p)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{2, 4}, refs)
}

func TestRoaringMemPostings_PostingsForAllLabelValues(t *testing.T) {
	mp := NewRoaringMemPostings()
	mp.Add(1, labels.FromStrings("foo", "1"))
	mp.Add(2, labels.FromStrings("foo", "2"))
	mp.Add(3, labels.FromStrings("foo", "3"))
	mp.Add(4, labels.FromStrings("foo", "4"))

	p := mp.PostingsForAllLabelValues(context.Background(), "foo")
	require.NoError(t, p.Err())
	refs, err := ExpandPostings(p)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 2, 3, 4}, refs)
}

func TestRoaringMemPostings_PostingsForLabelMatchingHonorsContextCancel(t *testing.T) {
	memP := NewRoaringMemPostings()
	seriesCount := 10 * checkContextEveryNIterations
	for i := 1; i <= seriesCount; i++ {
		memP.Add(storage.SeriesRef(i), labels.FromStrings("__name__", fmt.Sprintf("%4d", i)))
	}

	failAfter := uint64(seriesCount / 2 / checkContextEveryNIterations)
	ctx := &testutil.MockContextErrAfter{FailAfter: failAfter}
	p := memP.PostingsForLabelMatching(ctx, "__name__", func(string) bool {
		return true
	})
	require.Error(t, p.Err())
	require.Equal(t, failAfter+1, ctx.Count())
}

func TestRoaringMemPostings_Postings_MultipleValues(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("lbl", "a"))
	p.Add(2, labels.FromStrings("lbl", "b"))
	p.Add(3, labels.FromStrings("lbl", "c"))
	p.Add(4, labels.FromStrings("lbl", "a"))

	// Query for multiple values.
	it := p.Postings(context.Background(), "lbl", "a", "c")
	refs, err := ExpandPostings(it)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 3, 4}, refs)
}

func TestRoaringMemPostings_Add_OutOfOrder(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(5, labels.FromStrings("lbl", "a"))
	p.Add(1, labels.FromStrings("lbl", "a"))
	p.Add(3, labels.FromStrings("lbl", "a"))
	p.Add(2, labels.FromStrings("lbl", "a"))
	p.Add(4, labels.FromStrings("lbl", "a"))

	it := p.Postings(context.Background(), "lbl", "a")
	refs, err := ExpandPostings(it)
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 2, 3, 4, 5}, refs)
}

func TestRoaringPostings_Seek(t *testing.T) {
	p := NewRoaringMemPostings()
	for i := 1; i <= 10; i++ {
		p.Add(storage.SeriesRef(i), labels.FromStrings("lbl", "a"))
	}

	it := p.Postings(context.Background(), "lbl", "a")

	// Seek to the beginning.
	require.True(t, it.Seek(1))
	require.Equal(t, storage.SeriesRef(1), it.At())

	// Seek forward.
	require.True(t, it.Seek(5))
	require.Equal(t, storage.SeriesRef(5), it.At())

	// Seek to current value (should return true without advancing).
	require.True(t, it.Seek(5))
	require.Equal(t, storage.SeriesRef(5), it.At())

	// Seek to value past current but present.
	require.True(t, it.Seek(8))
	require.Equal(t, storage.SeriesRef(8), it.At())

	// Seek past the end.
	require.False(t, it.Seek(11))
}

func TestRoaringPostings_SeekToGap(t *testing.T) {
	p := NewRoaringMemPostings()
	for _, ref := range []storage.SeriesRef{1, 3, 5, 7, 9} {
		p.Add(ref, labels.FromStrings("lbl", "a"))
	}

	it := p.Postings(context.Background(), "lbl", "a")

	// Seek to a value that doesn't exist; should land on next.
	require.True(t, it.Seek(4))
	require.Equal(t, storage.SeriesRef(5), it.At())

	require.True(t, it.Seek(6))
	require.Equal(t, storage.SeriesRef(7), it.At())
}

func TestRoaringPostings_EmptyPostings(t *testing.T) {
	p := NewRoaringMemPostings()

	it := p.Postings(context.Background(), "nonexistent", "value")
	require.Equal(t, EmptyPostings(), it)
}

func TestRoaringPostings_Intersect(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "1", "b", "1"))
	p.Add(2, labels.FromStrings("a", "1", "b", "2"))
	p.Add(3, labels.FromStrings("a", "2", "b", "1"))

	a1 := p.Postings(context.Background(), "a", "1")
	b1 := p.Postings(context.Background(), "b", "1")

	res, err := ExpandPostings(Intersect(a1, b1))
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1}, res)
}

func TestRoaringPostings_Without(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "1"))
	p.Add(2, labels.FromStrings("a", "1"))
	p.Add(3, labels.FromStrings("a", "1"))

	drop := NewListPostings([]storage.SeriesRef{2})

	full := p.Postings(context.Background(), "a", "1")
	res, err := ExpandPostings(Without(full, drop))
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 3}, res)
}

func TestRoaringMemPostings_LabelNames(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "1", "b", "2"))
	p.Add(2, labels.FromStrings("c", "3"))

	names := p.LabelNames()
	require.ElementsMatch(t, []string{"a", "b", "c"}, names)
}

func TestRoaringMemPostings_LabelValues(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "x"))
	p.Add(2, labels.FromStrings("a", "y"))
	p.Add(3, labels.FromStrings("a", "z"))

	vals := p.LabelValues(context.Background(), "a", nil)
	require.ElementsMatch(t, []string{"x", "y", "z"}, vals)
}

func TestRoaringMemPostings_All(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "1"))
	p.Add(2, labels.FromStrings("b", "2"))
	p.Add(3, labels.FromStrings("c", "3"))

	refs, err := ExpandPostings(p.All())
	require.NoError(t, err)
	require.Equal(t, []storage.SeriesRef{1, 2, 3}, refs)
}

func TestRoaringMemPostings_Iter(t *testing.T) {
	p := NewRoaringMemPostings()
	p.Add(1, labels.FromStrings("a", "1"))
	p.Add(2, labels.FromStrings("a", "1"))

	found := map[string][]storage.SeriesRef{}
	err := p.Iter(func(l labels.Label, postings Postings) error {
		refs, err := ExpandPostings(postings)
		if err != nil {
			return err
		}
		found[l.Name+"="+l.Value] = refs
		return nil
	})
	require.NoError(t, err)

	require.Equal(t, []storage.SeriesRef{1, 2}, found["a=1"])
	require.Equal(t, []storage.SeriesRef{1, 2}, found["="])
}
